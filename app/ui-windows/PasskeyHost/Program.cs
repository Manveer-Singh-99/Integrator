// ==============================================================================================
// Integrator Windows 11 Packaged Passkey COM Host (`ui-windows/PasskeyHost/Program.cs`)
//
// 1. Module Purpose & System Scope:
//    - Dedicated, non-elevated (Medium-IL `asInvoker`), MSIX-packaged out-of-process COM local
//      server hosting `IPluginAuthenticator` (`{D26BCF6F-B54C-43FF-9F06-D5BF148625F7}`) for
//      Windows 11 24H2+ native WebAuthn passkey integration ("Integrator Touch ID").
//    - Separated from the elevated (`requireAdministrator`) WinUI 3 `Integrator.exe` process so
//      Windows Security (`BioEnrollmentHost` / `webauthn.dll` / COM SCM) can activate CLSID
//      `{4B2C1F30-8A1E-4509-913A-96696EF07BC3}` at Medium IL with valid sparse MSIX Package
//      Identity (`Integrator.PasskeyProvider`).
//    - Decodes CTAP2 CBOR MakeCredential / GetAssertion requests via `webauthn.dll`, delegates
//      stateless encrypted `TransportSessionV2` RPCs to the paired macOS workstation via
//      `integrator_cli.exe passkey make-hex|assert-hex` (which prompts hardware Apple Touch ID),
//      encodes canonical CTAP2 CBOR responses, and updates Windows passkey autofill metadata.
//
// 2. Architectural Linkages & Dependencies:
//    - Upstream Caller: Windows COM SCM via `AppxManifest.xml` `<com:ExeServer>` declaration
//      (`IntegratorPasskeyHost.exe -PluginActivated`), plus CLI admin commands (`--register`,
//      `--unregister`, `--status`, `--self-test`).
//    - Downstream Bridge: `integrator_cli.exe` located in the same deployment directory, which
//      reads DPAPI-protected `KeystoreV2` credentials and executes `TransportSessionV2` RPCs to
//      macOS port 58281.
//    - Downstream Win32 APIs: `ole32.dll` (`CoInitializeSecurity`, `CoRegisterClassObject`,
//      `CoRevokeClassObject`), `webauthn.dll` (`WebAuthNPluginAddAuthenticator2`,
//      `WebAuthNPluginRemoveAuthenticator`, `WebAuthNPluginGetAuthenticatorState`,
//      `WebAuthNPluginAuthenticatorAddCredentials`, `WebAuthNPluginAuthenticatorGetAllCredentials`,
//      `WebAuthNDecode*`, `WebAuthNEncode*`), `kernel32.dll` (`GetCurrentPackageFullName`),
//      `user32.dll` (`GetMessageW`, `TranslateMessage`, `DispatchMessageW`, `PostQuitMessage`).
//
// 3. Threading & Concurrency Model:
//    - Main thread runs as an STA (`[STAThread]`) pumping Win32/COM messages (`GetMessageW`) so
//      out-of-process COM RPC calls on `IPluginAuthenticator` dispatch cleanly.
//    - A private synchronization lock (`_operationLock`) serializes active WebAuthn ceremonies to
//      prevent overlapping Touch ID prompts on the paired Mac.
//    - Subprocess invocations to `integrator_cli.exe` enforce a bounded 55-second timeout matching
//      macOS `TOUCHID_RPC_RECV_TIMEOUT` (50s) plus margin.
//
// 4. Security & Safety Invariants:
//    - Zero Private Keys on Windows: All ECDSA P-256 passkey private keys remain exclusively in
//      the paired macOS encrypted keystore gated by physical Apple Touch ID biometrics.
//    - Exact Win32 ABI Alignment: Every `webauthn.h` (API v9, `WEBAUTHN_CREDENTIAL_ATTESTATION`
//      v8, `WEBAUTHN_ASSERTION` v6) and `webauthnplugin.h` (`WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS`)
//      struct matches the Windows 10.0.26100.0 SDK headers byte-for-byte.
//    - Zero Use-After-Free / Clean COM Ownership: `WebAuthNEncode*` output buffers are allocated
//      by Windows via `CoTaskMemAlloc` and transferred directly to COM out-parameters; unmanaged
//      input allocations are freed strictly after all native calls using them return.
// ==============================================================================================

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;

namespace IntegratorPasskeyHost
{
    // ==========================================================================================
    // COM Interface Definitions (Matching pluginauthenticator.idl Byte-for-Byte)
    // ==========================================================================================

    /// <summary>Windows 11 24H2+ native WebAuthn plugin authenticator COM contract.</summary>
    [ComImport]
    [Guid(Constants.IidIPluginAuthenticatorString)]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IPluginAuthenticator
    {
        /// <summary>Creates a new resident passkey credential gated by macOS Touch ID.</summary>
        [PreserveSig]
        int MakeCredential(
            in WEBAUTHN_PLUGIN_OPERATION_REQUEST request,
            out WEBAUTHN_PLUGIN_OPERATION_RESPONSE response);

        /// <summary>Signs a WebAuthn assertion for an existing resident passkey via macOS Touch ID.</summary>
        [PreserveSig]
        int GetAssertion(
            in WEBAUTHN_PLUGIN_OPERATION_REQUEST request,
            out WEBAUTHN_PLUGIN_OPERATION_RESPONSE response);

        /// <summary>Cancels an in-flight WebAuthn operation.</summary>
        [PreserveSig]
        int CancelOperation(
            in WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST request);

        /// <summary>Reports vault lock status (0 = PluginLocked, 1 = PluginUnlocked).</summary>
        [PreserveSig]
        int GetLockStatus(
            out int lockStatus);
    }

    /// <summary>Standard COM Class Factory interface registered with CoRegisterClassObject.</summary>
    [ComImport]
    [Guid(Constants.IidIClassFactoryString)]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IClassFactory
    {
        /// <summary>Instantiates the requested COM interface on the plugin authenticator.</summary>
        [PreserveSig]
        int CreateInstance(IntPtr pUnkOuter, ref Guid riid, out IntPtr ppvObject);

        /// <summary>Locks or unlocks the local COM server in memory.</summary>
        [PreserveSig]
        int LockServer([MarshalAs(UnmanagedType.Bool)] bool fLock);
    }

    // ==========================================================================================
    // Protocol Constants & Named Win32 Values (Strictly Zero Inline Literals)
    // ==========================================================================================

    internal static class Constants
    {
        /// <summary>COM CLSID string registered in AppxManifest.xml and WebAuthNPluginAddAuthenticator2.</summary>
        public const string ClsidIntegratorPasskeyString = "4b2c1f30-8a1e-4509-913a-96696ef07bc3";

        /// <summary>IID string for Windows IPluginAuthenticator.</summary>
        public const string IidIPluginAuthenticatorString = "d26bcf6f-b54c-43ff-9f06-d5bf148625f7";

        /// <summary>IID string for COM IClassFactory.</summary>
        public const string IidIClassFactoryString = "00000001-0000-0000-C000-000000000046";

        /// <summary>IID string for COM IUnknown.</summary>
        public const string IidIUnknownString = "00000000-0000-0000-C000-000000000046";

        /// <summary>Parsed CLSID GUID for Integrator Touch ID plugin.</summary>
        public static readonly Guid ClsidIntegratorPasskey = new(ClsidIntegratorPasskeyString);

        /// <summary>Parsed IID GUID for IPluginAuthenticator.</summary>
        public static readonly Guid IidIPluginAuthenticator = new(IidIPluginAuthenticatorString);

        /// <summary>Parsed IID GUID for IUnknown.</summary>
        public static readonly Guid IidIUnknown = new(IidIUnknownString);

        /// <summary>Display name shown in Windows Settings and Passkey picker dialogs.</summary>
        public const string AuthenticatorDisplayName = "Integrator Touch ID";

        /// <summary>Plugin Relying Party identifier required by WebAuthNPluginAddAuthenticator2.</summary>
        public const string PluginRpId = "integrator.local";

        /// <summary>Canonical WebAuthn credential type string.</summary>
        public const string CredentialTypePublicKey = "public-key";

        /// <summary>Canonical WebAuthn attestation format string for self/none attestation.</summary>
        public const string AttestationTypeNone = "none";

        /// <summary>Log filename placed under user profile for passkey diagnostics.</summary>
        public const string PasskeyLogFileName = ".integrator_passkey.log";

        /// <summary>Companion Rust CLI executable name deployed beside IntegratorPasskeyHost.exe.</summary>
        public const string CompanionCliExeName = "integrator_cli.exe";

        /// <summary>COM activation argument declared in AppxManifest.xml com:ExeServer.</summary>
        public const string ArgPluginActivated = "-PluginActivated";

        /// <summary>CLI flag to register or re-register the plugin with Windows WebAuthn.</summary>
        public const string ArgRegister = "--register";

        /// <summary>CLI flag to unregister the plugin from Windows WebAuthn.</summary>
        public const string ArgUnregister = "--unregister";

        /// <summary>CLI flag to inspect package identity, state, and cached credentials.</summary>
        public const string ArgStatus = "--status";

        /// <summary>CLI flag to verify ABI struct marshaling against webauthn.dll encode APIs.</summary>
        public const string ArgSelfTest = "--self-test";

        /// <summary>COM CLSCTX_LOCAL_SERVER flag for out-of-process executable servers.</summary>
        public const uint ClsctxLocalServer = 0x04u;

        /// <summary>COM REGCLS_MULTIPLEUSE flag permitting multiple client bindings.</summary>
        public const uint RegclsMultipleUse = 0x01u;

        /// <summary>CoInitializeSecurity authentication level: RPC_C_AUTHN_LEVEL_DEFAULT.</summary>
        public const uint RpcCAuthnLevelDefault = 0u;

        /// <summary>CoInitializeSecurity impersonation level: RPC_C_IMP_LEVEL_IMPERSONATE.</summary>
        public const uint RpcCImpLevelImpersonate = 3u;

        /// <summary>CoInitializeSecurity capability flag: EOAC_NONE.</summary>
        public const uint EoacNone = 0u;

        /// <summary>CoInitializeSecurity server auth count: automatic default (-1).</summary>
        public const int ComAuthSvcDefault = -1;

        /// <summary>COM S_OK status code.</summary>
        public const int S_OK = 0;

        /// <summary>COM E_FAIL status code.</summary>
        public const int E_FAIL = unchecked((int)0x80004005);

        /// <summary>COM E_INVALIDARG status code.</summary>
        public const int E_INVALIDARG = unchecked((int)0x80070057);

        /// <summary>COM E_NOINTERFACE status code.</summary>
        public const int E_NOINTERFACE = unchecked((int)0x80004002);

        /// <summary>COM CLASS_E_NOAGGREGATION status code.</summary>
        public const int CLASS_E_NOAGGREGATION = unchecked((int)0x80040110);

        /// <summary>Win32 NTE_EXISTS (plugin already registered).</summary>
        public const int NTE_EXISTS = unchecked((int)0x8009000F);

        /// <summary>Win32 NTE_NOT_FOUND (no matching credential or plugin not registered).</summary>
        public const int NTE_NOT_FOUND = unchecked((int)0x80090011);

        /// <summary>Win32 NTE_USER_CANCELLED (user declined or timed out Touch ID).</summary>
        public const int NTE_USER_CANCELLED = unchecked((int)0x80090036);

        /// <summary>Win32 ERROR_SUCCESS for GetCurrentPackageFullName.</summary>
        public const int ErrorSuccess = 0;

        /// <summary>Win32 ERROR_INSUFFICIENT_BUFFER for GetCurrentPackageFullName.</summary>
        public const int ErrorInsufficientBuffer = 122;

        /// <summary>Plugin lock status value: PluginUnlocked (1).</summary>
        public const int PluginLockStatusUnlocked = 1;

        /// <summary>WEBAUTHN_CREDENTIAL_VERSION_1 (1).</summary>
        public const uint WebAuthnCredentialVersion1 = 1u;

        /// <summary>WEBAUTHN_USER_ENTITY_INFORMATION_CURRENT_VERSION (1).</summary>
        public const uint WebAuthnUserEntityInfoVersion1 = 1u;

        /// <summary>WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION (8, SDK 10.0.26100.0).</summary>
        public const uint WebAuthnCredentialAttestationVersion8 = 8u;

        /// <summary>WEBAUTHN_ASSERTION_CURRENT_VERSION (6, SDK 10.0.26100.0).</summary>
        public const uint WebAuthnAssertionVersion6 = 6u;

        /// <summary>WEBAUTHN_ATTESTATION_DECODE_NONE (0).</summary>
        public const uint WebAuthnAttestationDecodeNone = 0u;

        /// <summary>Timeout in milliseconds waiting for integrator_cli.exe Touch ID RPC (55 seconds).</summary>
        public const int CliRpcTimeoutMs = 55000;

        /// <summary>Idle timeout in milliseconds before exiting a COM-activated host if no call arrives (15 minutes).</summary>
        public const int IdleExitTimeoutMs = 15 * 60 * 1000;

        /// <summary>Standard Base64-encoded Integrator Touch ID SVG logo (light theme).</summary>
        public const string LogoSvgBase64 =
            "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZlcnNpb249IjEuMSIgdmlld0JveD0iMCAwIDY0IDY0Ij4" +
            "8cmVjdCB3aWR0aD0iNjQiIGhlaWdodD0iNjQiIHJ4PSIxNCIgZmlsbD0iIzBkNmVmZCIvPjxjaXJjbGUgY3g9IjMyIiBjeT0iM" +
            "zIiIHI9IjE4IiBmaWxsPSJub25lIiBzdHJva2U9IndoaXRlIiBzdHJva2Utd2lkdGg9IjQiLz48Y2lyY2xlIGN4PSIzMiIgY3k" +
            "9IjMyIiByPSIxMCIgZmlsbD0ibm9uZSIgc3Ryb2tlPSJ3aGl0ZSIgc3Ryb2tlLXdpZHRoPSI0Ii8+PGNpcmNsZSBjeD0iMzIiI" +
            "GN5PSIzMiIgcj0iMyIgZmlsbD0id2hpdGUiLz48L3N2Zz4=";

        /// <summary>
        /// Canonical CTAP2 authenticatorGetInfo CBOR payload matching Microsoft PasskeyManager:
        /// {
        ///   1: ["FIDO_2_0", "FIDO_2_1"],
        ///   3: h'd9a4a4e12fbc4b57908da247e16806f4' (Integrator AAGUID),
        ///   4: {"rk": true, "up": true, "uv": true},
        ///   9: ["internal"],
        ///  10: [{"alg": -7, "type": "public-key"}]
        /// }
        /// </summary>
        public static readonly byte[] AuthenticatorGetInfoCbor = new byte[]
        {
            0xa5,
            // 1: ["FIDO_2_0", "FIDO_2_1"]
            0x01, 0x82,
                0x68, 0x46, 0x49, 0x44, 0x4f, 0x5f, 0x32, 0x5f, 0x30,
                0x68, 0x46, 0x49, 0x44, 0x4f, 0x5f, 0x32, 0x5f, 0x31,
            // 3: 16-byte AAGUID (d9a4a4e1-2fbc-4b57-908d-a247e16806f4)
            0x03, 0x50,
                0xd9, 0xa4, 0xa4, 0xe1, 0x2f, 0xbc, 0x4b, 0x57,
                0x90, 0x8d, 0xa2, 0x47, 0xe1, 0x68, 0x06, 0xf4,
            // 4: {"rk": true, "up": true, "uv": true}
            0x04, 0xa3,
                0x62, 0x72, 0x6b, 0xf5,
                0x62, 0x75, 0x70, 0xf5,
                0x62, 0x75, 0x76, 0xf5,
            // 9: ["internal"]
            0x09, 0x81,
                0x68, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c,
            // 10: [{"alg": -7, "type": "public-key"}]
            0x0a, 0x81, 0xa2,
                0x63, 0x61, 0x6c, 0x67, 0x26,
                0x64, 0x74, 0x79, 0x70, 0x65, 0x6a, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0x2d, 0x6b, 0x65, 0x79
        };
    }

    // ==========================================================================================
    // Exact Win32 ABI Structs Verified Against Windows SDK 10.0.26100.0 webauthn.h / webauthnplugin.h
    // ==========================================================================================

    /// <summary>Incoming operation request structure from pluginauthenticator.idl.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct WEBAUTHN_PLUGIN_OPERATION_REQUEST
    {
        public IntPtr hWnd;
        public Guid transactionId;
        public uint cbRequestSignature;
        public IntPtr pbRequestSignature;
        public int requestType;
        public uint cbEncodedRequest;
        public IntPtr pbEncodedRequest;
    }

    /// <summary>Outgoing operation response structure from pluginauthenticator.idl.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct WEBAUTHN_PLUGIN_OPERATION_RESPONSE
    {
        public uint cbEncodedResponse;
        public IntPtr pbEncodedResponse;
    }

    /// <summary>Incoming cancellation request structure from pluginauthenticator.idl.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST
    {
        public Guid transactionId;
        public uint cbRequestSignature;
        public IntPtr pbRequestSignature;
    }

    /// <summary>Plugin registration options structure from webauthnplugin.h (v2).</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS_2
    {
        public string pwszAuthenticatorName;
        public IntPtr pClsid;
        public string pwszPluginRpId;
        public string? pwszLightThemeLogoSvg;
        public string? pwszDarkThemeLogoSvg;
        public uint cbAuthenticatorInfo;
        public IntPtr pbAuthenticatorInfo;
        public uint cSupportedRpIds;
        public IntPtr ppwszSupportedRpIds;
        public string? pwszUserVerificationKeyName;
    }

    /// <summary>Relying party entity structure from webauthn.h.</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WEBAUTHN_RP_ENTITY_INFORMATION
    {
        public uint dwVersion;
        public string? pwszId;
        public string? pwszName;
        public string? pwszIcon;
    }

    /// <summary>User entity structure from webauthn.h.</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WEBAUTHN_USER_ENTITY_INFORMATION
    {
        public uint dwVersion;
        public uint cbId;
        public IntPtr pbId;
        public string? pwszName;
        public string? pwszIcon;
        public string? pwszDisplayName;
    }

    /// <summary>COSE credential parameters array header from webauthn.h.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct WEBAUTHN_COSE_CREDENTIAL_PARAMETERS
    {
        public uint cCredentialParameters;
        public IntPtr pCredentialParameters;
    }

    /// <summary>Credential descriptor (WEBAUTHN_CREDENTIAL) from webauthn.h:278.</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WEBAUTHN_CREDENTIAL
    {
        public uint dwVersion;
        public uint cbId;
        public IntPtr pbId;
        public string? pwszCredentialType;
    }

    /// <summary>Extended credential descriptor (WEBAUTHN_CREDENTIAL_EX) from webauthn.h:315.</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WEBAUTHN_CREDENTIAL_EX
    {
        public uint dwVersion;
        public uint cbId;
        public IntPtr pbId;
        public string? pwszCredentialType;
        public uint dwTransports;
    }

    /// <summary>Credential pointer list (WEBAUTHN_CREDENTIAL_LIST) from webauthn.h.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct WEBAUTHN_CREDENTIAL_LIST
    {
        public uint cCredentials;
        public IntPtr ppCredentials;
    }

    /// <summary>WebAuthn extensions array header from webauthn.h:668.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct WEBAUTHN_EXTENSIONS
    {
        public uint cExtensions;
        public IntPtr pExtensions;
    }

    /// <summary>Decoded CTAP2 MakeCredential request header from webauthnplugin.h:456.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST
    {
        public uint dwVersion;
        public uint cbRpId;
        public IntPtr pbRpId;
        public uint cbClientDataHash;
        public IntPtr pbClientDataHash;
        public IntPtr pRpInformation;
        public IntPtr pUserInformation;
        public WEBAUTHN_COSE_CREDENTIAL_PARAMETERS WebAuthNCredentialParameters;
        public WEBAUTHN_CREDENTIAL_LIST CredentialList;
    }

    /// <summary>Decoded CTAP2 GetAssertion request header from webauthnplugin.h:558.</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST
    {
        public uint dwVersion;
        public string? pwszRpId;
        public uint cbRpId;
        public IntPtr pbRpId;
        public uint cbClientDataHash;
        public IntPtr pbClientDataHash;
        public WEBAUTHN_CREDENTIAL_LIST CredentialList;
    }

    /// <summary>Full v8 WEBAUTHN_CREDENTIAL_ATTESTATION matching Windows SDK 10.0.26100.0 webauthn.h:1056.</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WEBAUTHN_CREDENTIAL_ATTESTATION
    {
        // Version 1
        public uint dwVersion;
        public string? pwszFormatType;
        public uint cbAuthenticatorData;
        public IntPtr pbAuthenticatorData;
        public uint cbAttestation;
        public IntPtr pbAttestation;
        public uint dwAttestationDecodeType;
        public IntPtr pvAttestationDecode;
        public uint cbAttestationObject;
        public IntPtr pbAttestationObject;
        public uint cbCredentialId;
        public IntPtr pbCredentialId;
        // Version 2
        public WEBAUTHN_EXTENSIONS Extensions;
        // Version 3
        public uint dwUsedTransport;
        // Version 4
        public int bEpAtt;
        public int bLargeBlobSupported;
        public int bResidentKey;
        // Version 5
        public int bPrfEnabled;
        // Version 6
        public uint cbUnsignedExtensionOutputs;
        public IntPtr pbUnsignedExtensionOutputs;
        // Version 7
        public IntPtr pHmacSecret;
        public int bThirdPartyPayment;
        // Version 8
        public uint dwTransports;
        public uint cbClientDataJSON;
        public IntPtr pbClientDataJSON;
        public uint cbRegistrationResponseJSON;
        public IntPtr pbRegistrationResponseJSON;
    }

    /// <summary>Full v6 WEBAUTHN_ASSERTION matching Windows SDK 10.0.26100.0 webauthn.h:1185.</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WEBAUTHN_ASSERTION
    {
        // Version 1
        public uint dwVersion;
        public uint cbAuthenticatorData;
        public IntPtr pbAuthenticatorData;
        public uint cbSignature;
        public IntPtr pbSignature;
        public WEBAUTHN_CREDENTIAL Credential;
        public uint cbUserId;
        public IntPtr pbUserId;
        // Version 2
        public WEBAUTHN_EXTENSIONS Extensions;
        public uint cbCredLargeBlob;
        public IntPtr pbCredLargeBlob;
        public uint dwCredLargeBlobStatus;
        // Version 3
        public IntPtr pHmacSecret;
        // Version 4
        public uint dwUsedTransport;
        // Version 5
        public uint cbUnsignedExtensionOutputs;
        public IntPtr pbUnsignedExtensionOutputs;
        // Version 6
        public uint cbClientDataJSON;
        public IntPtr pbClientDataJSON;
        public uint cbAuthenticationResponseJSON;
        public IntPtr pbAuthenticationResponseJSON;
    }

    /// <summary>Full WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE matching webauthnplugin.h:631.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE
    {
        public WEBAUTHN_ASSERTION WebAuthNAssertion;
        public IntPtr pUserInformation;
        public uint dwNumberOfCredentials;
        public int lUserSelected;
        public uint cbLargeBlobKey;
        public IntPtr pbLargeBlobKey;
        public uint cbUnsignedExtensionOutputs;
        public IntPtr pbUnsignedExtensionOutputs;
    }

    /// <summary>Exact WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS matching webauthnplugin.h:219.</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS
    {
        public uint cbCredentialId;
        public IntPtr pbCredentialId;
        public string pwszRpId;
        public string pwszRpName;
        public uint cbUserId;
        public IntPtr pbUserId;
        public string pwszUserName;
        public string pwszUserDisplayName;
    }

    /// <summary>Win32 MSG structure for the STA COM message pump.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct MSG
    {
        public IntPtr hwnd;
        public uint message;
        public UIntPtr wParam;
        public IntPtr lParam;
        public uint time;
        public int ptX;
        public int ptY;
    }

    // ==========================================================================================
    // JSON DTOs for integrator_cli.exe Bridge
    // ==========================================================================================

    internal sealed class MakeCredRequestDto
    {
        [JsonPropertyName("client_data_hash_hex")] public string ClientDataHashHex { get; set; } = string.Empty;
        [JsonPropertyName("rp_id")] public string RpId { get; set; } = string.Empty;
        [JsonPropertyName("user_id_hex")] public string UserIdHex { get; set; } = string.Empty;
        [JsonPropertyName("user_name")] public string UserName { get; set; } = string.Empty;
        [JsonPropertyName("user_display_name")] public string UserDisplayName { get; set; } = string.Empty;
        [JsonPropertyName("requester_hostname")] public string RequesterHostname { get; set; } = Environment.MachineName;
    }

    internal sealed class MakeCredResponseDto
    {
        [JsonPropertyName("credential_id_hex")] public string CredentialIdHex { get; set; } = string.Empty;
        [JsonPropertyName("auth_data_hex")] public string AuthDataHex { get; set; } = string.Empty;
        [JsonPropertyName("attestation_format")] public string AttestationFormat { get; set; } = Constants.AttestationTypeNone;
        [JsonPropertyName("attestation_object_cbor_hex")] public string AttestationObjectCborHex { get; set; } = string.Empty;
    }

    internal sealed class GetAssertRequestDto
    {
        [JsonPropertyName("client_data_hash_hex")] public string ClientDataHashHex { get; set; } = string.Empty;
        [JsonPropertyName("rp_id")] public string RpId { get; set; } = string.Empty;
        [JsonPropertyName("allow_credential_ids_hex")] public List<string> AllowCredentialIdsHex { get; set; } = new();
        [JsonPropertyName("requester_hostname")] public string RequesterHostname { get; set; } = Environment.MachineName;
    }

    internal sealed class GetAssertResponseDto
    {
        [JsonPropertyName("credential_id_hex")] public string CredentialIdHex { get; set; } = string.Empty;
        [JsonPropertyName("user_id_hex")] public string UserIdHex { get; set; } = string.Empty;
        [JsonPropertyName("auth_data_hex")] public string AuthDataHex { get; set; } = string.Empty;
        [JsonPropertyName("signature_der_hex")] public string SignatureDerHex { get; set; } = string.Empty;
        [JsonPropertyName("sign_count")] public uint SignCount { get; set; }
    }

    internal sealed class CliEnvelope<T>
    {
        [JsonPropertyName("ok")] public bool Ok { get; set; }
        [JsonPropertyName("data")] public T? Data { get; set; }
        [JsonPropertyName("error")] public string? Error { get; set; }
        [JsonPropertyName("not_found")] public bool NotFound { get; set; }
    }

    // ==========================================================================================
    // Native Win32 Interop Declarations
    // ==========================================================================================

    internal static class NativeMethods
    {
        [DllImport("ole32.dll")]
        public static extern int CoInitializeSecurity(
            IntPtr pSecDesc,
            int cAuthSvc,
            IntPtr asAuthSvc,
            IntPtr pReserved1,
            uint dwAuthnLevel,
            uint dwImpLevel,
            IntPtr pAuthList,
            uint dwCapabilities,
            IntPtr pReserved3);

        [DllImport("ole32.dll")]
        public static extern int CoRegisterClassObject(
            ref Guid rclsid,
            [MarshalAs(UnmanagedType.IUnknown)] object pUnk,
            uint dwClsContext,
            uint flags,
            out uint lpdwRegister);

        [DllImport("ole32.dll")]
        public static extern int CoRevokeClassObject(uint dwRegister);

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
        public static extern int GetCurrentPackageFullName(
            ref uint packageFullNameLength,
            StringBuilder? packageFullName);

        [DllImport("user32.dll")]
        public static extern int GetMessageW(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax);

        [DllImport("user32.dll")]
        public static extern bool TranslateMessage(ref MSG lpMsg);

        [DllImport("user32.dll")]
        public static extern IntPtr DispatchMessageW(ref MSG lpMsg);

        [DllImport("user32.dll")]
        public static extern void PostQuitMessage(int nExitCode);

        [DllImport("webauthn.dll", CharSet = CharSet.Unicode)]
        public static extern int WebAuthNPluginAddAuthenticator2(
            ref WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS_2 options,
            out IntPtr ppResponse);

        [DllImport("webauthn.dll")]
        public static extern void WebAuthNPluginFreeAddAuthenticatorResponse(IntPtr pResponse);

        [DllImport("webauthn.dll")]
        public static extern int WebAuthNPluginRemoveAuthenticator(ref Guid rclsid);

        [DllImport("webauthn.dll")]
        public static extern int WebAuthNPluginGetAuthenticatorState(ref Guid rclsid, out int state);

        [DllImport("webauthn.dll")]
        public static extern int WebAuthNPluginAuthenticatorAddCredentials(
            ref Guid rclsid,
            uint cCredentialDetails,
            IntPtr pCredentialDetails);

        [DllImport("webauthn.dll")]
        public static extern int WebAuthNPluginAuthenticatorGetAllCredentials(
            ref Guid rclsid,
            out uint pcCredentialDetails,
            out IntPtr ppCredentialDetailsArray);

        [DllImport("webauthn.dll")]
        public static extern void WebAuthNPluginAuthenticatorFreeCredentialDetailsArray(
            uint cCredentialDetails,
            IntPtr pCredentialDetailsArray);

        [DllImport("webauthn.dll")]
        public static extern int WebAuthNDecodeMakeCredentialRequest(
            uint cbEncoded,
            IntPtr pbEncoded,
            out IntPtr ppMakeCredentialRequest);

        [DllImport("webauthn.dll")]
        public static extern void WebAuthNFreeDecodedMakeCredentialRequest(IntPtr pMakeCredentialRequest);

        [DllImport("webauthn.dll")]
        public static extern int WebAuthNEncodeMakeCredentialResponse(
            ref WEBAUTHN_CREDENTIAL_ATTESTATION pCredentialAttestation,
            out uint pcbResp,
            out IntPtr ppbResp);

        [DllImport("webauthn.dll")]
        public static extern int WebAuthNDecodeGetAssertionRequest(
            uint cbEncoded,
            IntPtr pbEncoded,
            out IntPtr ppGetAssertionRequest);

        [DllImport("webauthn.dll")]
        public static extern void WebAuthNFreeDecodedGetAssertionRequest(IntPtr pGetAssertionRequest);

        [DllImport("webauthn.dll")]
        public static extern int WebAuthNEncodeGetAssertionResponse(
            ref WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE pGetAssertionResponse,
            out uint pcbResp,
            out IntPtr ppbResp);
    }

    // ==========================================================================================
    // Logger Helper
    // ==========================================================================================

    internal static class PasskeyLogger
    {
        private static readonly object LogLock = new();
        private static readonly string LogPath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            Constants.PasskeyLogFileName);

        public static void Write(string message)
        {
            string line = $"[{DateTime.UtcNow:O}] [PasskeyHost pid={Environment.ProcessId}] {message}";
            lock (LogLock)
            {
                try
                {
                    File.AppendAllText(LogPath, line + Environment.NewLine);
                }
                catch { }
            }
            try
            {
                Console.WriteLine(line);
            }
            catch { }
        }
    }

    // ==========================================================================================
    // IPluginAuthenticator & IClassFactory COM Implementation
    // ==========================================================================================

    internal sealed class IntegratorPluginAuthenticator : IPluginAuthenticator
    {
        private readonly object _operationLock = new();

        public int GetLockStatus(out int lockStatus)
        {
            PasskeyLogger.Write("GetLockStatus() called -> returning PluginUnlocked (1)");
            lockStatus = Constants.PluginLockStatusUnlocked;
            return Constants.S_OK;
        }

        public int CancelOperation(in WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST request)
        {
            PasskeyLogger.Write($"CancelOperation(tx={request.transactionId}) called");
            return Constants.S_OK;
        }

        public int MakeCredential(
            in WEBAUTHN_PLUGIN_OPERATION_REQUEST request,
            out WEBAUTHN_PLUGIN_OPERATION_RESPONSE response)
        {
            response = default;
            PasskeyLogger.Write($"MakeCredential(tx={request.transactionId}, cbReq={request.cbEncodedRequest}) invoked by Windows");

            if (request.cbEncodedRequest == 0 || request.pbEncodedRequest == IntPtr.Zero)
            {
                return Constants.E_INVALIDARG;
            }

            lock (_operationLock)
            {
                IntPtr pDecoded = IntPtr.Zero;
                IntPtr pAuthData = IntPtr.Zero;
                IntPtr pCredId = IntPtr.Zero;
                IntPtr pUserId = IntPtr.Zero;
                IntPtr pDetails = IntPtr.Zero;
                try
                {
                    int hrDecode = NativeMethods.WebAuthNDecodeMakeCredentialRequest(
                        request.cbEncodedRequest,
                        request.pbEncodedRequest,
                        out pDecoded);

                    if (hrDecode != Constants.S_OK || pDecoded == IntPtr.Zero)
                    {
                        PasskeyLogger.Write($"WebAuthNDecodeMakeCredentialRequest failed: HR=0x{hrDecode:X8}");
                        return hrDecode != Constants.S_OK ? hrDecode : Constants.E_FAIL;
                    }

                    var decoded = Marshal.PtrToStructure<WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST>(pDecoded);

                    // Extract Relying Party ID & friendly name
                    string rpId = string.Empty;
                    string rpName = string.Empty;
                    if (decoded.pRpInformation != IntPtr.Zero)
                    {
                        var rp = Marshal.PtrToStructure<WEBAUTHN_RP_ENTITY_INFORMATION>(decoded.pRpInformation);
                        rpId = rp.pwszId ?? string.Empty;
                        rpName = rp.pwszName ?? rpId;
                    }
                    if (string.IsNullOrEmpty(rpId) && decoded.cbRpId > 0 && decoded.pbRpId != IntPtr.Zero)
                    {
                        byte[] rpBytes = new byte[decoded.cbRpId];
                        Marshal.Copy(decoded.pbRpId, rpBytes, 0, (int)decoded.cbRpId);
                        rpId = Encoding.UTF8.GetString(rpBytes);
                        if (string.IsNullOrEmpty(rpName)) rpName = rpId;
                    }

                    // Extract 32-byte clientDataHash
                    byte[] cdhBytes = new byte[decoded.cbClientDataHash];
                    if (decoded.pbClientDataHash != IntPtr.Zero && decoded.cbClientDataHash > 0)
                    {
                        Marshal.Copy(decoded.pbClientDataHash, cdhBytes, 0, (int)decoded.cbClientDataHash);
                    }
                    string clientDataHashHex = Convert.ToHexString(cdhBytes).ToLowerInvariant();

                    // Extract User Entity info
                    string userName = "user";
                    string userDisplayName = "User";
                    byte[] userIdBytes = new byte[] { 0x00 };
                    if (decoded.pUserInformation != IntPtr.Zero)
                    {
                        var user = Marshal.PtrToStructure<WEBAUTHN_USER_ENTITY_INFORMATION>(decoded.pUserInformation);
                        userName = string.IsNullOrEmpty(user.pwszName) ? "user" : user.pwszName;
                        userDisplayName = string.IsNullOrEmpty(user.pwszDisplayName) ? userName : user.pwszDisplayName;
                        if (user.cbId > 0 && user.pbId != IntPtr.Zero)
                        {
                            userIdBytes = new byte[user.cbId];
                            Marshal.Copy(user.pbId, userIdBytes, 0, (int)user.cbId);
                        }
                    }
                    string userIdHex = Convert.ToHexString(userIdBytes).ToLowerInvariant();

                    PasskeyLogger.Write($"MakeCredential decoded: rpId='{rpId}', user='{userName}' -> dispatching to Mac Touch ID");

                    var rpcReq = new MakeCredRequestDto
                    {
                        RpId = rpId,
                        ClientDataHashHex = clientDataHashHex,
                        UserIdHex = userIdHex,
                        UserName = userName,
                        UserDisplayName = userDisplayName,
                        RequesterHostname = Environment.MachineName
                    };

                    var rpcRes = CliBridge.Invoke<MakeCredResponseDto>("make-hex", rpcReq);
                    if (rpcRes == null || !rpcRes.Ok || rpcRes.Data == null || string.IsNullOrEmpty(rpcRes.Data.AuthDataHex))
                    {
                        PasskeyLogger.Write($"Mac Touch ID MakeCredential failed/cancelled: {rpcRes?.Error ?? "null response"}");
                        return Constants.NTE_USER_CANCELLED;
                    }

                    byte[] authDataBytes = Convert.FromHexString(rpcRes.Data.AuthDataHex);
                    byte[] credIdBytes = Convert.FromHexString(rpcRes.Data.CredentialIdHex);

                    pAuthData = Marshal.AllocHGlobal(authDataBytes.Length);
                    Marshal.Copy(authDataBytes, 0, pAuthData, authDataBytes.Length);

                    pCredId = Marshal.AllocHGlobal(credIdBytes.Length);
                    Marshal.Copy(credIdBytes, 0, pCredId, credIdBytes.Length);

                    // Match Microsoft PasskeyManager PluginAuthenticatorImpl.cpp:686-703
                    var att = new WEBAUTHN_CREDENTIAL_ATTESTATION
                    {
                        dwVersion = Constants.WebAuthnCredentialAttestationVersion8,
                        pwszFormatType = Constants.AttestationTypeNone,
                        cbAuthenticatorData = (uint)authDataBytes.Length,
                        pbAuthenticatorData = pAuthData,
                        cbAttestation = 0,
                        pbAttestation = IntPtr.Zero,
                        dwAttestationDecodeType = Constants.WebAuthnAttestationDecodeNone,
                        pvAttestationDecode = IntPtr.Zero
                    };

                    int hrEncode = NativeMethods.WebAuthNEncodeMakeCredentialResponse(
                        ref att,
                        out uint cbResp,
                        out IntPtr pbResp);

                    if (hrEncode != Constants.S_OK || pbResp == IntPtr.Zero)
                    {
                        PasskeyLogger.Write($"WebAuthNEncodeMakeCredentialResponse failed: HR=0x{hrEncode:X8}");
                        return hrEncode != Constants.S_OK ? hrEncode : Constants.E_FAIL;
                    }

                    // Register newly created passkey metadata into Windows Credential Manager autofill cache
                    try
                    {
                        pUserId = Marshal.AllocHGlobal(userIdBytes.Length);
                        Marshal.Copy(userIdBytes, 0, pUserId, userIdBytes.Length);

                        var pluginCred = new WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS
                        {
                            cbCredentialId = (uint)credIdBytes.Length,
                            pbCredentialId = pCredId,
                            pwszRpId = rpId,
                            pwszRpName = string.IsNullOrEmpty(rpName) ? rpId : rpName,
                            cbUserId = (uint)userIdBytes.Length,
                            pbUserId = pUserId,
                            pwszUserName = userName,
                            pwszUserDisplayName = userDisplayName
                        };

                        pDetails = Marshal.AllocHGlobal(Marshal.SizeOf<WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS>());
                        Marshal.StructureToPtr(pluginCred, pDetails, false);
                        Guid clsid = Constants.ClsidIntegratorPasskey;
                        int hrAddCred = NativeMethods.WebAuthNPluginAuthenticatorAddCredentials(ref clsid, 1u, pDetails);
                        PasskeyLogger.Write($"WebAuthNPluginAuthenticatorAddCredentials(rp='{rpId}') HR=0x{hrAddCred:X8}");
                    }
                    catch (Exception addEx)
                    {
                        PasskeyLogger.Write($"AddCredentials non-fatal warning: {addEx.Message}");
                    }

                    response.cbEncodedResponse = cbResp;
                    response.pbEncodedResponse = pbResp;
                    PasskeyLogger.Write($"MakeCredential succeeded! credId={rpcRes.Data.CredentialIdHex[..Math.Min(16, rpcRes.Data.CredentialIdHex.Length)]}... cbResp={cbResp}");
                    return Constants.S_OK;
                }
                catch (Exception ex)
                {
                    PasskeyLogger.Write($"MakeCredential exception: {ex}");
                    return Constants.E_FAIL;
                }
                finally
                {
                    if (pDetails != IntPtr.Zero)
                    {
                        Marshal.DestroyStructure<WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS>(pDetails);
                        Marshal.FreeHGlobal(pDetails);
                    }
                    if (pUserId != IntPtr.Zero) Marshal.FreeHGlobal(pUserId);
                    if (pCredId != IntPtr.Zero) Marshal.FreeHGlobal(pCredId);
                    if (pAuthData != IntPtr.Zero) Marshal.FreeHGlobal(pAuthData);
                    if (pDecoded != IntPtr.Zero) NativeMethods.WebAuthNFreeDecodedMakeCredentialRequest(pDecoded);
                }
            }
        }

        public int GetAssertion(
            in WEBAUTHN_PLUGIN_OPERATION_REQUEST request,
            out WEBAUTHN_PLUGIN_OPERATION_RESPONSE response)
        {
            response = default;
            PasskeyLogger.Write($"GetAssertion(tx={request.transactionId}, cbReq={request.cbEncodedRequest}) invoked by Windows");

            if (request.cbEncodedRequest == 0 || request.pbEncodedRequest == IntPtr.Zero)
            {
                return Constants.E_INVALIDARG;
            }

            lock (_operationLock)
            {
                IntPtr pDecoded = IntPtr.Zero;
                IntPtr pAuthData = IntPtr.Zero;
                IntPtr pSig = IntPtr.Zero;
                IntPtr pCredId = IntPtr.Zero;
                IntPtr pUserId = IntPtr.Zero;
                IntPtr pUserEntity = IntPtr.Zero;
                try
                {
                    int hrDecode = NativeMethods.WebAuthNDecodeGetAssertionRequest(
                        request.cbEncodedRequest,
                        request.pbEncodedRequest,
                        out pDecoded);

                    if (hrDecode != Constants.S_OK || pDecoded == IntPtr.Zero)
                    {
                        PasskeyLogger.Write($"WebAuthNDecodeGetAssertionRequest failed: HR=0x{hrDecode:X8}");
                        return hrDecode != Constants.S_OK ? hrDecode : Constants.E_FAIL;
                    }

                    var decoded = Marshal.PtrToStructure<WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST>(pDecoded);

                    string rpId = decoded.pwszRpId ?? string.Empty;
                    if (string.IsNullOrEmpty(rpId) && decoded.cbRpId > 0 && decoded.pbRpId != IntPtr.Zero)
                    {
                        byte[] rpBytes = new byte[decoded.cbRpId];
                        Marshal.Copy(decoded.pbRpId, rpBytes, 0, (int)decoded.cbRpId);
                        rpId = Encoding.UTF8.GetString(rpBytes);
                    }

                    byte[] cdhBytes = new byte[decoded.cbClientDataHash];
                    if (decoded.pbClientDataHash != IntPtr.Zero && decoded.cbClientDataHash > 0)
                    {
                        Marshal.Copy(decoded.pbClientDataHash, cdhBytes, 0, (int)decoded.cbClientDataHash);
                    }
                    string clientDataHashHex = Convert.ToHexString(cdhBytes).ToLowerInvariant();

                    var allowList = new List<string>();
                    if (decoded.CredentialList.cCredentials > 0 && decoded.CredentialList.ppCredentials != IntPtr.Zero)
                    {
                        int ptrSize = IntPtr.Size;
                        for (int i = 0; i < decoded.CredentialList.cCredentials; i++)
                        {
                            IntPtr credPtr = Marshal.ReadIntPtr(decoded.CredentialList.ppCredentials, i * ptrSize);
                            if (credPtr != IntPtr.Zero)
                            {
                                var cred = Marshal.PtrToStructure<WEBAUTHN_CREDENTIAL_EX>(credPtr);
                                if (cred.cbId > 0 && cred.pbId != IntPtr.Zero)
                                {
                                    byte[] idBytes = new byte[cred.cbId];
                                    Marshal.Copy(cred.pbId, idBytes, 0, (int)cred.cbId);
                                    allowList.Add(Convert.ToHexString(idBytes).ToLowerInvariant());
                                }
                            }
                        }
                    }

                    PasskeyLogger.Write($"GetAssertion decoded: rpId='{rpId}', allowCount={allowList.Count} -> dispatching to Mac Touch ID");

                    var rpcReq = new GetAssertRequestDto
                    {
                        RpId = rpId,
                        ClientDataHashHex = clientDataHashHex,
                        AllowCredentialIdsHex = allowList,
                        RequesterHostname = Environment.MachineName
                    };

                    var rpcRes = CliBridge.Invoke<GetAssertResponseDto>("assert-hex", rpcReq);
                    if (rpcRes == null || !rpcRes.Ok || rpcRes.Data == null || string.IsNullOrEmpty(rpcRes.Data.SignatureDerHex))
                    {
                        PasskeyLogger.Write($"Mac Touch ID GetAssertion failed: notFound={rpcRes?.NotFound}, err={rpcRes?.Error ?? "null"}");
                        return (rpcRes != null && rpcRes.NotFound)
                            ? Constants.NTE_NOT_FOUND
                            : Constants.NTE_USER_CANCELLED;
                    }

                    byte[] authDataBytes = Convert.FromHexString(rpcRes.Data.AuthDataHex);
                    byte[] sigBytes = Convert.FromHexString(rpcRes.Data.SignatureDerHex);
                    byte[] credIdBytes = Convert.FromHexString(rpcRes.Data.CredentialIdHex);
                    byte[] userIdBytes = string.IsNullOrEmpty(rpcRes.Data.UserIdHex)
                        ? Array.Empty<byte>()
                        : Convert.FromHexString(rpcRes.Data.UserIdHex);

                    pAuthData = Marshal.AllocHGlobal(authDataBytes.Length);
                    Marshal.Copy(authDataBytes, 0, pAuthData, authDataBytes.Length);

                    pSig = Marshal.AllocHGlobal(sigBytes.Length);
                    Marshal.Copy(sigBytes, 0, pSig, sigBytes.Length);

                    pCredId = Marshal.AllocHGlobal(credIdBytes.Length);
                    Marshal.Copy(credIdBytes, 0, pCredId, credIdBytes.Length);

                    if (userIdBytes.Length > 0)
                    {
                        pUserId = Marshal.AllocHGlobal(userIdBytes.Length);
                        Marshal.Copy(userIdBytes, 0, pUserId, userIdBytes.Length);

                        var userEntity = new WEBAUTHN_USER_ENTITY_INFORMATION
                        {
                            dwVersion = Constants.WebAuthnUserEntityInfoVersion1,
                            cbId = (uint)userIdBytes.Length,
                            pbId = pUserId
                        };
                        pUserEntity = Marshal.AllocHGlobal(Marshal.SizeOf<WEBAUTHN_USER_ENTITY_INFORMATION>());
                        Marshal.StructureToPtr(userEntity, pUserEntity, false);
                    }

                    // Match Microsoft PasskeyManager PluginAuthenticatorImpl.cpp:1068-1118
                    var assertResp = new WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE
                    {
                        WebAuthNAssertion = new WEBAUTHN_ASSERTION
                        {
                            dwVersion = Constants.WebAuthnAssertionVersion6,
                            cbAuthenticatorData = (uint)authDataBytes.Length,
                            pbAuthenticatorData = pAuthData,
                            cbSignature = (uint)sigBytes.Length,
                            pbSignature = pSig,
                            Credential = new WEBAUTHN_CREDENTIAL
                            {
                                dwVersion = Constants.WebAuthnCredentialVersion1,
                                cbId = (uint)credIdBytes.Length,
                                pbId = pCredId,
                                pwszCredentialType = Constants.CredentialTypePublicKey
                            },
                            cbUserId = (uint)userIdBytes.Length,
                            pbUserId = pUserId
                        },
                        pUserInformation = pUserEntity,
                        dwNumberOfCredentials = 1u
                    };

                    int hrEncode = NativeMethods.WebAuthNEncodeGetAssertionResponse(
                        ref assertResp,
                        out uint cbResp,
                        out IntPtr pbResp);

                    if (hrEncode != Constants.S_OK || pbResp == IntPtr.Zero)
                    {
                        PasskeyLogger.Write($"WebAuthNEncodeGetAssertionResponse failed: HR=0x{hrEncode:X8}");
                        return hrEncode != Constants.S_OK ? hrEncode : Constants.E_FAIL;
                    }

                    response.cbEncodedResponse = cbResp;
                    response.pbEncodedResponse = pbResp;
                    PasskeyLogger.Write($"GetAssertion succeeded! signCount={rpcRes.Data.SignCount}, cbResp={cbResp}");
                    return Constants.S_OK;
                }
                catch (Exception ex)
                {
                    PasskeyLogger.Write($"GetAssertion exception: {ex}");
                    return Constants.E_FAIL;
                }
                finally
                {
                    if (pUserEntity != IntPtr.Zero) Marshal.FreeHGlobal(pUserEntity);
                    if (pUserId != IntPtr.Zero) Marshal.FreeHGlobal(pUserId);
                    if (pCredId != IntPtr.Zero) Marshal.FreeHGlobal(pCredId);
                    if (pSig != IntPtr.Zero) Marshal.FreeHGlobal(pSig);
                    if (pAuthData != IntPtr.Zero) Marshal.FreeHGlobal(pAuthData);
                    if (pDecoded != IntPtr.Zero) NativeMethods.WebAuthNFreeDecodedGetAssertionRequest(pDecoded);
                }
            }
        }
    }

    internal sealed class IntegratorPluginClassFactory : IClassFactory
    {
        private readonly IntegratorPluginAuthenticator _authenticator = new();

        public int CreateInstance(IntPtr pUnkOuter, ref Guid riid, out IntPtr ppvObject)
        {
            ppvObject = IntPtr.Zero;
            PasskeyLogger.Write($"IClassFactory.CreateInstance(riid={riid})");

            if (pUnkOuter != IntPtr.Zero)
            {
                return Constants.CLASS_E_NOAGGREGATION;
            }

            if (riid == Constants.IidIPluginAuthenticator)
            {
                ppvObject = Marshal.GetComInterfaceForObject(_authenticator, typeof(IPluginAuthenticator));
                return Constants.S_OK;
            }

            if (riid == Constants.IidIUnknown)
            {
                ppvObject = Marshal.GetIUnknownForObject(_authenticator);
                return Constants.S_OK;
            }

            return Constants.E_NOINTERFACE;
        }

        public int LockServer(bool fLock)
        {
            PasskeyLogger.Write($"IClassFactory.LockServer(fLock={fLock})");
            return Constants.S_OK;
        }
    }

    // ==========================================================================================
    // Companion Rust CLI Subprocess Bridge (Stateless TransportSessionV2 Client)
    // ==========================================================================================

    internal static class CliBridge
    {
        public static CliEnvelope<T>? Invoke<T>(string subcommand, object payload)
        {
            string cliPath = Path.Combine(AppContext.BaseDirectory, Constants.CompanionCliExeName);
            if (!File.Exists(cliPath))
            {
                PasskeyLogger.Write($"Companion CLI missing at '{cliPath}'");
                return new CliEnvelope<T> { Ok = false, Error = $"Missing {Constants.CompanionCliExeName}" };
            }

            string json = JsonSerializer.Serialize(payload);
            string hexArg = Convert.ToHexString(Encoding.UTF8.GetBytes(json)).ToLowerInvariant();

            var psi = new ProcessStartInfo
            {
                FileName = cliPath,
                Arguments = $"passkey {subcommand} {hexArg}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true,
                WorkingDirectory = AppContext.BaseDirectory
            };

            using var proc = Process.Start(psi);
            if (proc == null)
            {
                return new CliEnvelope<T> { Ok = false, Error = "Failed to spawn companion CLI" };
            }

            string stdout = proc.StandardOutput.ReadToEnd();
            string stderr = proc.StandardError.ReadToEnd();
            if (!proc.WaitForExit(Constants.CliRpcTimeoutMs))
            {
                try { proc.Kill(entireProcessTree: true); } catch { }
                return new CliEnvelope<T> { Ok = false, Error = "Touch ID RPC timed out" };
            }

            if (!string.IsNullOrWhiteSpace(stderr))
            {
                PasskeyLogger.Write($"CLI stderr: {stderr.Trim()}");
            }

            string trimmed = stdout.Trim();
            if (string.IsNullOrEmpty(trimmed))
            {
                return new CliEnvelope<T> { Ok = false, Error = $"Empty CLI output (exit={proc.ExitCode})" };
            }

            // Use the last JSON line in case tracing output preceded it
            string[] lines = trimmed.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            string lastLine = lines[^1];
            return JsonSerializer.Deserialize<CliEnvelope<T>>(lastLine);
        }
    }

    // ==========================================================================================
    // Entry Point & Lifecycle Modes
    // ==========================================================================================

    internal static class Program
    {
        private static string QueryPackageFullName()
        {
            uint len = 0;
            int rc = NativeMethods.GetCurrentPackageFullName(ref len, null);
            if (rc == Constants.ErrorInsufficientBuffer && len > 0)
            {
                var sb = new StringBuilder((int)len);
                rc = NativeMethods.GetCurrentPackageFullName(ref len, sb);
                if (rc == Constants.ErrorSuccess)
                {
                    return sb.ToString();
                }
            }
            return $"(unpackaged, rc={rc})";
        }

        private static int RunRegister()
        {
            string pkg = QueryPackageFullName();
            PasskeyLogger.Write($"--register starting under PackageFullName='{pkg}'");

            Guid clsid = Constants.ClsidIntegratorPasskey;
            int hrRem = NativeMethods.WebAuthNPluginRemoveAuthenticator(ref clsid);
            PasskeyLogger.Write($"WebAuthNPluginRemoveAuthenticator HR=0x{hrRem:X8}");

            IntPtr pClsid = Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
            IntPtr pCbor = Marshal.AllocHGlobal(Constants.AuthenticatorGetInfoCbor.Length);
            try
            {
                Marshal.StructureToPtr(clsid, pClsid, false);
                Marshal.Copy(Constants.AuthenticatorGetInfoCbor, 0, pCbor, Constants.AuthenticatorGetInfoCbor.Length);

                var opts = new WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS_2
                {
                    pwszAuthenticatorName = Constants.AuthenticatorDisplayName,
                    pClsid = pClsid,
                    pwszPluginRpId = Constants.PluginRpId,
                    pwszLightThemeLogoSvg = Constants.LogoSvgBase64,
                    pwszDarkThemeLogoSvg = Constants.LogoSvgBase64,
                    cbAuthenticatorInfo = (uint)Constants.AuthenticatorGetInfoCbor.Length,
                    pbAuthenticatorInfo = pCbor,
                    cSupportedRpIds = 0u,
                    ppwszSupportedRpIds = IntPtr.Zero,
                    pwszUserVerificationKeyName = null
                };

                int hrAdd = NativeMethods.WebAuthNPluginAddAuthenticator2(ref opts, out IntPtr pResp);
                if (pResp != IntPtr.Zero)
                {
                    NativeMethods.WebAuthNPluginFreeAddAuthenticatorResponse(pResp);
                }

                PasskeyLogger.Write($"WebAuthNPluginAddAuthenticator2 HR=0x{hrAdd:X8}");
                if (hrAdd == Constants.S_OK || hrAdd == Constants.NTE_EXISTS)
                {
                    int hrState = NativeMethods.WebAuthNPluginGetAuthenticatorState(ref clsid, out int state);
                    PasskeyLogger.Write($"GetAuthenticatorState HR=0x{hrState:X8} State={state} (0=Disabled, 1=Enabled)");
                    return 0;
                }
                return 1;
            }
            finally
            {
                Marshal.FreeHGlobal(pClsid);
                Marshal.FreeHGlobal(pCbor);
            }
        }

        private static int RunUnregister()
        {
            Guid clsid = Constants.ClsidIntegratorPasskey;
            int hr = NativeMethods.WebAuthNPluginRemoveAuthenticator(ref clsid);
            PasskeyLogger.Write($"--unregister HR=0x{hr:X8} (pkg='{QueryPackageFullName()}')");
            return (hr == Constants.S_OK || hr == Constants.NTE_NOT_FOUND) ? 0 : 1;
        }

        private static int RunStatus()
        {
            string pkg = QueryPackageFullName();
            Guid clsid = Constants.ClsidIntegratorPasskey;
            int hrState = NativeMethods.WebAuthNPluginGetAuthenticatorState(ref clsid, out int state);
            int hrCreds = NativeMethods.WebAuthNPluginAuthenticatorGetAllCredentials(ref clsid, out uint count, out IntPtr arr);
            if (hrCreds == Constants.S_OK && arr != IntPtr.Zero)
            {
                NativeMethods.WebAuthNPluginAuthenticatorFreeCredentialDetailsArray(count, arr);
            }
            PasskeyLogger.Write(
                $"--status Package='{pkg}' StateHR=0x{hrState:X8} State={state} CredsHR=0x{hrCreds:X8} CachedCreds={count}");
            return 0;
        }

        private static int RunSelfTest()
        {
            // Verify WebAuthNEncodeMakeCredentialResponse & WebAuthNEncodeGetAssertionResponse ABI alignment live
            byte[] fakeAuthData = new byte[37];
            fakeAuthData[32] = 0x1D; // UP|UV|BE|BS
            byte[] fakeSig = new byte[] { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01 };
            byte[] fakeCredId = new byte[32];
            byte[] fakeUserId = new byte[] { 0x01, 0x02, 0x03, 0x04 };

            IntPtr pAuth = Marshal.AllocHGlobal(fakeAuthData.Length);
            IntPtr pSig = Marshal.AllocHGlobal(fakeSig.Length);
            IntPtr pCred = Marshal.AllocHGlobal(fakeCredId.Length);
            IntPtr pUser = Marshal.AllocHGlobal(fakeUserId.Length);
            IntPtr pUserEnt = Marshal.AllocHGlobal(Marshal.SizeOf<WEBAUTHN_USER_ENTITY_INFORMATION>());
            try
            {
                Marshal.Copy(fakeAuthData, 0, pAuth, fakeAuthData.Length);
                Marshal.Copy(fakeSig, 0, pSig, fakeSig.Length);
                Marshal.Copy(fakeCredId, 0, pCred, fakeCredId.Length);
                Marshal.Copy(fakeUserId, 0, pUser, fakeUserId.Length);

                var att = new WEBAUTHN_CREDENTIAL_ATTESTATION
                {
                    dwVersion = Constants.WebAuthnCredentialAttestationVersion8,
                    pwszFormatType = Constants.AttestationTypeNone,
                    cbAuthenticatorData = (uint)fakeAuthData.Length,
                    pbAuthenticatorData = pAuth
                };
                int hrMake = NativeMethods.WebAuthNEncodeMakeCredentialResponse(ref att, out uint cbMake, out IntPtr pbMake);
                if (pbMake != IntPtr.Zero) Marshal.FreeCoTaskMem(pbMake);

                var ue = new WEBAUTHN_USER_ENTITY_INFORMATION
                {
                    dwVersion = Constants.WebAuthnUserEntityInfoVersion1,
                    cbId = (uint)fakeUserId.Length,
                    pbId = pUser
                };
                Marshal.StructureToPtr(ue, pUserEnt, false);

                var assertResp = new WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE
                {
                    WebAuthNAssertion = new WEBAUTHN_ASSERTION
                    {
                        dwVersion = Constants.WebAuthnAssertionVersion6,
                        cbAuthenticatorData = (uint)fakeAuthData.Length,
                        pbAuthenticatorData = pAuth,
                        cbSignature = (uint)fakeSig.Length,
                        pbSignature = pSig,
                        Credential = new WEBAUTHN_CREDENTIAL
                        {
                            dwVersion = Constants.WebAuthnCredentialVersion1,
                            cbId = (uint)fakeCredId.Length,
                            pbId = pCred,
                            pwszCredentialType = Constants.CredentialTypePublicKey
                        },
                        cbUserId = (uint)fakeUserId.Length,
                        pbUserId = pUser
                    },
                    pUserInformation = pUserEnt,
                    dwNumberOfCredentials = 1u
                };
                int hrAssert = NativeMethods.WebAuthNEncodeGetAssertionResponse(ref assertResp, out uint cbAssert, out IntPtr pbAssert);
                if (pbAssert != IntPtr.Zero) Marshal.FreeCoTaskMem(pbAssert);

                PasskeyLogger.Write($"--self-test EncodeMake HR=0x{hrMake:X8} ({cbMake}B), EncodeAssert HR=0x{hrAssert:X8} ({cbAssert}B)");
                return (hrMake == Constants.S_OK && hrAssert == Constants.S_OK) ? 0 : 1;
            }
            finally
            {
                Marshal.FreeHGlobal(pUserEnt);
                Marshal.FreeHGlobal(pUser);
                Marshal.FreeHGlobal(pCred);
                Marshal.FreeHGlobal(pSig);
                Marshal.FreeHGlobal(pAuth);
            }
        }

        private static int RunComServer()
        {
            string pkg = QueryPackageFullName();
            PasskeyLogger.Write($"Starting COM LocalServer under PackageFullName='{pkg}'");

            int hrSec = NativeMethods.CoInitializeSecurity(
                IntPtr.Zero,
                Constants.ComAuthSvcDefault,
                IntPtr.Zero,
                IntPtr.Zero,
                Constants.RpcCAuthnLevelDefault,
                Constants.RpcCImpLevelImpersonate,
                IntPtr.Zero,
                Constants.EoacNone,
                IntPtr.Zero);
            PasskeyLogger.Write($"CoInitializeSecurity HR=0x{hrSec:X8}");

            var factory = new IntegratorPluginClassFactory();
            Guid clsid = Constants.ClsidIntegratorPasskey;
            int hrReg = NativeMethods.CoRegisterClassObject(
                ref clsid,
                factory,
                Constants.ClsctxLocalServer,
                Constants.RegclsMultipleUse,
                out uint cookie);

            PasskeyLogger.Write($"CoRegisterClassObject(CLSID={clsid}) HR=0x{hrReg:X8} cookie={cookie}");
            if (hrReg != Constants.S_OK)
            {
                return 1;
            }

            using var idleTimer = new System.Threading.Timer(_ =>
            {
                PasskeyLogger.Write("Idle timeout elapsed without active COM calls; posting WM_QUIT.");
                NativeMethods.PostQuitMessage(0);
            }, null, Constants.IdleExitTimeoutMs, System.Threading.Timeout.Infinite);

            try
            {
                // Standard STA message pump so out-of-process COM RPCs dispatch cleanly
                while (NativeMethods.GetMessageW(out MSG msg, IntPtr.Zero, 0u, 0u) > 0)
                {
                    // Reset idle watchdog timer on every window/RPC message
                    idleTimer.Change(Constants.IdleExitTimeoutMs, System.Threading.Timeout.Infinite);
                    NativeMethods.TranslateMessage(ref msg);
                    NativeMethods.DispatchMessageW(ref msg);
                }
            }
            finally
            {
                NativeMethods.CoRevokeClassObject(cookie);
                PasskeyLogger.Write("COM LocalServer revoked and exiting.");
            }
            return 0;
        }

        [STAThread]
        public static int Main(string[] args)
        {
            PasskeyLogger.Write($"Main(args=[{string.Join(" ", args)}])");
            foreach (string arg in args)
            {
                if (string.Equals(arg, Constants.ArgRegister, StringComparison.OrdinalIgnoreCase))
                {
                    return RunRegister();
                }
                if (string.Equals(arg, Constants.ArgUnregister, StringComparison.OrdinalIgnoreCase))
                {
                    return RunUnregister();
                }
                if (string.Equals(arg, Constants.ArgStatus, StringComparison.OrdinalIgnoreCase))
                {
                    return RunStatus();
                }
                if (string.Equals(arg, Constants.ArgSelfTest, StringComparison.OrdinalIgnoreCase))
                {
                    return RunSelfTest();
                }
            }

            return RunComServer();
        }
    }
}
