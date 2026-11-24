// ==============================================================================================
// Integrator Windows Passkey Plugin Authenticator (`ui-windows/PasskeyAuthenticatorPlugin.cs`)
//
// 1. Module Purpose & System Scope:
//    - Implements the Windows 11 24H2+ native WebAuthn plugin authenticator architecture via `IPluginAuthenticator`
//      (`{D26BCF6F-B54C-43FF-9F06-D5BF148625F7}`) and `IClassFactory` (`{00000001-0000-0000-C000-000000000046}`).
//    - Exposes the local workstation as an OS-registered FIDO2/WebAuthn Passkey Provider ("Integrator Touch ID").
//    - Decodes incoming CTAP2 CBOR MakeCredential and GetAssertion operations dispatched by Windows browsers
//      (Edge, Chrome, Brave) using native Win32 `WebAuthNDecode*` APIs in `webauthn.dll`.
//    - Dispatches cryptographic operations across `TransportSessionV2` to the paired macOS workstation, where
//      physical Apple Touch ID hardware biometric authentication gates private key signing.
//    - Formats and returns canonical WebAuthn attestation objects and signed assertion payloads to Windows.
//
// 2. Architectural Linkages & Native Core Bridge:
//    - Upstream Caller: Windows WebAuthn subsystem (`C:\Windows\System32\webauthn.dll`) via COM invocation
//      (`CoCreateInstance` on CLSID `{4B2C1F30-8A1E-4509-913A-96696EF07BC3}`).
//    - Downstream Core: Interacts with `integrator_core.dll` via `CoreBridge.Invoke<T>`:
//        * `passkey_make_credential_remote`: Requests remote Mac to prompt Touch ID and create credential.
//        * `passkey_get_assertion_remote`: Requests remote Mac to prompt Touch ID and sign assertion.
//    - Downstream Win32 OS APIs:
//        * `webauthn.dll`: `WebAuthNPluginAddAuthenticator2`, `WebAuthNPluginGetAuthenticatorState`,
//          `WebAuthNDecodeMakeCredentialRequest`, `WebAuthNEncodeMakeCredentialResponse`,
//          `WebAuthNDecodeGetAssertionRequest`, `WebAuthNEncodeGetAssertionResponse`,
//          `WebAuthNPluginAuthenticatorAddCredentials`.
//        * `ole32.dll`: `CoRegisterClassObject`, `CoRevokeClassObject`.
//    - Cross-Platform & Remote Coordination:
//        * Windows Browser -> Windows WebAuthn -> COM `IPluginAuthenticator` -> C# -> `TransportSessionV2` ->
//          macOS `IntegratorCore` -> Apple LocalAuthentication Touch ID prompt -> macOS Secure Enclave signs
//          assertion -> `TransportSessionV2` -> Windows COM `IPluginAuthenticator` response -> Windows Browser.
//
// 3. Threading & Concurrency Model:
//    - COM Invocations: Windows dispatches COM RPC calls on worker threads (MTA or STA).
//    - Re-entrancy Synchronization: A private lock object (`_operationLock`) serializes WebAuthn transactions,
//      preventing concurrent conflicting biometric prompts.
//    - Non-Blocking Execution: Remote RPC calls across `TransportSessionV2` are awaited with a 50-second timeout.
//
// 4. Security & Safety Invariants:
//    - Biometric Hardware Binding: All assertions are strictly gated behind physical Apple Touch ID biometrics.
//    - Zero Private Keys on Windows: All cryptographic private keys remain strictly on the paired Mac
//      Secure Enclave / Keystore; Windows only processes public keys and signatures.
//    - Package Identity: The hosting process links to the sparse MSIX package `Integrator.PasskeyProvider`
//      via `app.manifest` `<msix>` block, satisfying Windows security boundary requirements.
//    - Native Pointer & DLL Search Hygiene: All P/Invokes enforce `[DefaultDllImportSearchPaths(DllImportSearchPath.System32)]`,
//      decoded Win32 lengths/counts are bounded, and all unmanaged allocations are deterministically freed in `finally`.
// ==============================================================================================

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text.Json.Serialization;
using System.Threading;

namespace IntegratorUI
{
    // ==========================================================================================
    // COM Interface Definitions
    // ==========================================================================================

    /// <summary>
    /// Windows 11 native WebAuthn plugin authenticator COM interface.
    /// Defined in Windows SDK <c>pluginauthenticator.idl</c> / <c>pluginauthenticator.h</c>.
    /// </summary>
    [ComImport]
    [Guid(PasskeyAuthenticatorPlugin.IID_IPluginAuthenticator_String)]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IPluginAuthenticator
    {
        /// <summary>
        /// Handles a WebAuthn credential creation request dispatched by Windows.
        /// </summary>
        [PreserveSig]
        int MakeCredential(
            in WEBAUTHN_PLUGIN_OPERATION_REQUEST request,
            out WEBAUTHN_PLUGIN_OPERATION_RESPONSE response);

        /// <summary>
        /// Handles a WebAuthn assertion/signing request dispatched by Windows.
        /// </summary>
        [PreserveSig]
        int GetAssertion(
            in WEBAUTHN_PLUGIN_OPERATION_REQUEST request,
            out WEBAUTHN_PLUGIN_OPERATION_RESPONSE response);

        /// <summary>
        /// Cancels an in-flight WebAuthn operation.
        /// </summary>
        [PreserveSig]
        int CancelOperation(
            in WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST request);

        /// <summary>
        /// Queries the vault lock status (0 = locked, 1 = unlocked).
        /// </summary>
        [PreserveSig]
        int GetLockStatus(
            out int lockStatus);
    }

    /// <summary>
    /// Standard COM Class Factory interface for object instantiation.
    /// </summary>
    [ComImport]
    [Guid("00000001-0000-0000-C000-000000000046")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    internal interface IClassFactory
    {
        /// <summary>Creates an uninitialized object instance.</summary>
        [PreserveSig]
        int CreateInstance(IntPtr pUnkOuter, ref Guid riid, out IntPtr ppvObject);

        /// <summary>Locks or unlocks the server in memory.</summary>
        [PreserveSig]
        int LockServer([MarshalAs(UnmanagedType.Bool)] bool fLock);
    }

    // ==========================================================================================
    // Win32 WebAuthn & COM Native Structs
    // ==========================================================================================

    /// <summary>Operation request payload passed to IPluginAuthenticator methods.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct WEBAUTHN_PLUGIN_OPERATION_REQUEST
    {
        /// <summary>Window handle of the calling browser window.</summary>
        public IntPtr hWnd;
        /// <summary>Unique transaction identifier.</summary>
        public Guid transactionId;
        /// <summary>Byte count of request signature.</summary>
        public uint cbRequestSignature;
        /// <summary>Pointer to request signature bytes.</summary>
        public IntPtr pbRequestSignature;
        /// <summary>Request format type (1 = CTAP2 CBOR).</summary>
        public int requestType;
        /// <summary>Byte count of encoded CTAP2 CBOR request payload.</summary>
        public uint cbEncodedRequest;
        /// <summary>Pointer to encoded CTAP2 CBOR request payload buffer.</summary>
        public IntPtr pbEncodedRequest;
    }

    /// <summary>Operation response payload returned by IPluginAuthenticator methods.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct WEBAUTHN_PLUGIN_OPERATION_RESPONSE
    {
        /// <summary>Byte count of encoded CTAP2 response payload.</summary>
        public uint cbEncodedResponse;
        /// <summary>Pointer to CoTaskMemAlloc-allocated encoded response buffer.</summary>
        public IntPtr pbEncodedResponse;
    }

    /// <summary>Cancellation request payload.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST
    {
        /// <summary>Transaction identifier to cancel.</summary>
        public Guid transactionId;
        /// <summary>Byte count of request signature.</summary>
        public uint cbRequestSignature;
        /// <summary>Pointer to request signature bytes.</summary>
        public IntPtr pbRequestSignature;
    }

    /// <summary>Options structure for WebAuthNPluginAddAuthenticator2.</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS_2
    {
        /// <summary>Display name of the authenticator.</summary>
        public string pwszAuthenticatorName;
        /// <summary>Pointer to CLSID GUID.</summary>
        public IntPtr pClsid;
        /// <summary>Plugin Relying Party identifier.</summary>
        public string pwszPluginRpId;
        /// <summary>Optional SVG logo for light theme.</summary>
        public string? pwszLightThemeLogoSvg;
        /// <summary>Optional SVG logo for dark theme.</summary>
        public string? pwszDarkThemeLogoSvg;
        /// <summary>Byte count of getInfo CBOR payload.</summary>
        public uint cbAuthenticatorInfo;
        /// <summary>Pointer to getInfo CBOR payload.</summary>
        public IntPtr pbAuthenticatorInfo;
        /// <summary>Supported RP IDs count (0 for all).</summary>
        public uint cSupportedRpIds;
        /// <summary>Pointer to supported RP IDs array.</summary>
        public IntPtr ppwszSupportedRpIds;
        /// <summary>Optional user verification key name.</summary>
        public string? pwszUserVerificationKeyName;
    }

    /// <summary>Relying party entity information decoded from WebAuthn request.</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WEBAUTHN_RP_ENTITY_INFORMATION
    {
        /// <summary>Structure version.</summary>
        public uint dwVersion;
        /// <summary>Relying Party domain identifier.</summary>
        public string pwszId;
        /// <summary>Relying Party display name.</summary>
        public string pwszName;
        /// <summary>Optional icon URL.</summary>
        public string pwszIcon;
    }

    /// <summary>User entity information decoded from WebAuthn request.</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WEBAUTHN_USER_ENTITY_INFORMATION
    {
        /// <summary>Structure version.</summary>
        public uint dwVersion;
        /// <summary>Byte count of user identifier.</summary>
        public uint cbId;
        /// <summary>Pointer to user identifier bytes.</summary>
        public IntPtr pbId;
        /// <summary>Username handle.</summary>
        public string pwszName;
        /// <summary>Optional user icon URL.</summary>
        public string pwszIcon;
        /// <summary>User display name.</summary>
        public string pwszDisplayName;
    }

    /// <summary>COSE credential parameters list.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct WEBAUTHN_COSE_CREDENTIAL_PARAMETERS
    {
        /// <summary>Count of parameters.</summary>
        public uint cCredentialParameters;
        /// <summary>Pointer to parameters array.</summary>
        public IntPtr pCredentialParameters;
    }

    /// <summary>List of credential descriptors.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct WEBAUTHN_CREDENTIAL_LIST
    {
        /// <summary>Count of credentials.</summary>
        public uint cCredentials;
        /// <summary>Pointer to array of WEBAUTHN_CREDENTIAL_EX pointers.</summary>
        public IntPtr ppCredentials;
    }

    /// <summary>Credential descriptor descriptor.</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WEBAUTHN_CREDENTIAL_EX
    {
        /// <summary>Structure version.</summary>
        public uint dwVersion;
        /// <summary>Byte count of credential ID.</summary>
        public uint cbId;
        /// <summary>Pointer to credential ID bytes.</summary>
        public IntPtr pbId;
        /// <summary>Credential type string (e.g., "public-key").</summary>
        public string pwszCredentialType;
        /// <summary>Transport flags.</summary>
        public uint dwTransports;
    }

    /// <summary>Decoded CTAP2 CBOR MakeCredential request structure.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct EXPERIMENTAL_WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST
    {
        /// <summary>Structure version.</summary>
        public uint dwVersion;
        /// <summary>Byte count of raw RP ID.</summary>
        public uint cbRpId;
        /// <summary>Pointer to raw RP ID bytes.</summary>
        public IntPtr pbRpId;
        /// <summary>Byte count of client data hash.</summary>
        public uint cbClientDataHash;
        /// <summary>Pointer to 32-byte client data hash buffer.</summary>
        public IntPtr pbClientDataHash;
        /// <summary>Pointer to WEBAUTHN_RP_ENTITY_INFORMATION.</summary>
        public IntPtr pRpInformation;
        /// <summary>Pointer to WEBAUTHN_USER_ENTITY_INFORMATION.</summary>
        public IntPtr pUserInformation;
        /// <summary>Credential parameters.</summary>
        public WEBAUTHN_COSE_CREDENTIAL_PARAMETERS WebAuthNCredentialParameters;
        /// <summary>Exclusion list.</summary>
        public WEBAUTHN_CREDENTIAL_LIST CredentialList;
    }

    /// <summary>Decoded CTAP2 CBOR GetAssertion request structure.</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct EXPERIMENTAL_WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST
    {
        /// <summary>Structure version.</summary>
        public uint dwVersion;
        /// <summary>Relying Party domain string.</summary>
        public string pwszRpId;
        /// <summary>Byte count of raw RP ID.</summary>
        public uint cbRpId;
        /// <summary>Pointer to raw RP ID bytes.</summary>
        public IntPtr pbRpId;
        /// <summary>Byte count of client data hash.</summary>
        public uint cbClientDataHash;
        /// <summary>Pointer to 32-byte client data hash buffer.</summary>
        public IntPtr pbClientDataHash;
        /// <summary>Allowed credentials inclusion list.</summary>
        public WEBAUTHN_CREDENTIAL_LIST CredentialList;
    }

    /// <summary>Attestation response structure for MakeCredential encoding.</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WEBAUTHN_CREDENTIAL_ATTESTATION
    {
        /// <summary>Structure version (1 = current).</summary>
        public uint dwVersion;
        /// <summary>Attestation format type string ("none").</summary>
        public string pwszFormatType;
        /// <summary>Byte count of authenticator data.</summary>
        public uint cbAuthenticatorData;
        /// <summary>Pointer to authenticator data buffer.</summary>
        public IntPtr pbAuthenticatorData;
        /// <summary>Byte count of attestation statement.</summary>
        public uint cbAttestation;
        /// <summary>Pointer to attestation statement buffer.</summary>
        public IntPtr pbAttestation;
        /// <summary>Byte count of attestation object.</summary>
        public uint cbAttestationObject;
        /// <summary>Pointer to attestation object buffer.</summary>
        public IntPtr pbAttestationObject;
        /// <summary>Byte count of credential ID.</summary>
        public uint cbCredentialId;
        /// <summary>Pointer to credential ID buffer.</summary>
        public IntPtr pbCredentialId;
        /// <summary>Credential details.</summary>
        public WEBAUTHN_CREDENTIAL_EX CredentialEx;
    }

    /// <summary>WebAuthn assertion signature structure.</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WEBAUTHN_ASSERTION
    {
        /// <summary>Structure version (1 = current).</summary>
        public uint dwVersion;
        /// <summary>Byte count of authenticator data.</summary>
        public uint cbAuthenticatorData;
        /// <summary>Pointer to authenticator data buffer.</summary>
        public IntPtr pbAuthenticatorData;
        /// <summary>Byte count of ECDSA signature bytes.</summary>
        public uint cbSignature;
        /// <summary>Pointer to ECDSA DER signature buffer.</summary>
        public IntPtr pbSignature;
        /// <summary>Asserted credential descriptor.</summary>
        public WEBAUTHN_CREDENTIAL_EX Credential;
        /// <summary>Byte count of user ID.</summary>
        public uint cbUserId;
        /// <summary>Pointer to user ID bytes.</summary>
        public IntPtr pbUserId;
    }

    /// <summary>Assertion response structure for GetAssertion encoding.</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct EXPERIMENTAL_WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE
    {
        /// <summary>Core assertion fields.</summary>
        public WEBAUTHN_ASSERTION WebAuthNAssertion;
        /// <summary>Optional user entity information pointer.</summary>
        public IntPtr pUserInformation;
        /// <summary>Total matching credentials count.</summary>
        public uint dwNumberOfCredentials;
        /// <summary>User selected index.</summary>
        public int lUserSelected;
        /// <summary>Large blob key byte count.</summary>
        public uint cbLargeBlobKey;
        /// <summary>Large blob key buffer pointer.</summary>
        public IntPtr pbLargeBlobKey;
        /// <summary>Unsigned extension outputs byte count.</summary>
        public uint cbUnsignedExtensionOutputs;
        /// <summary>Unsigned extension outputs buffer pointer.</summary>
        public IntPtr pbUnsignedExtensionOutputs;
    }

    /// <summary>Plugin credential metadata added to Windows credential manager cache.</summary>
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS
    {
        /// <summary>Structure version (1 = current).</summary>
        public uint dwVersion;
        /// <summary>Pointer to WEBAUTHN_USER_ENTITY_INFORMATION.</summary>
        public IntPtr pUserInformation;
        /// <summary>Pointer to WEBAUTHN_RP_ENTITY_INFORMATION.</summary>
        public IntPtr pRpInformation;
        /// <summary>Byte count of credential ID.</summary>
        public uint cbCredentialID;
        /// <summary>Pointer to credential ID bytes.</summary>
        public IntPtr pbCredentialID;
        /// <summary>Byte count of removable storage ID.</summary>
        public uint cbRemovableStorageID;
        /// <summary>Pointer to removable storage ID bytes.</summary>
        public IntPtr pbRemovableStorageID;
        /// <summary>True if credential is backed up.</summary>
        public bool bBackedUp;
    }

    // ==========================================================================================
    // JSON-RPC DTO Data Models for Remote Mac Bridge
    // ==========================================================================================

    /// <summary>Request DTO dispatched to Rust core to invoke remote Mac passkey creation.</summary>
    internal sealed class RemotePasskeyMakeCredentialDto
    {
        /// <summary>Optional target Mac peer IP override (null auto-selects best paired Mac).</summary>
        [JsonPropertyName("peer_ip")] public string? PeerIp { get; set; }
        /// <summary>MakeCredential request payload forwarded to macOS Secure Enclave.</summary>
        [JsonPropertyName("request")] public RemotePasskeyMakeCredRequestData Request { get; set; } = new();
    }

    /// <summary>MakeCredential inner request parameters.</summary>
    internal sealed class RemotePasskeyMakeCredRequestData
    {
        /// <summary>Hex-encoded 32-byte SHA-256 clientDataJSON hash.</summary>
        [JsonPropertyName("client_data_hash_hex")] public string ClientDataHashHex { get; set; } = string.Empty;
        /// <summary>Relying Party domain identifier (e.g., "github.com").</summary>
        [JsonPropertyName("rp_id")] public string RpId { get; set; } = string.Empty;
        /// <summary>Hex-encoded WebAuthn user handle byte array.</summary>
        [JsonPropertyName("user_id_hex")] public string UserIdHex { get; set; } = string.Empty;
        /// <summary>Account username handle.</summary>
        [JsonPropertyName("user_name")] public string UserName { get; set; } = string.Empty;
        /// <summary>Human-readable account display name.</summary>
        [JsonPropertyName("user_display_name")] public string UserDisplayName { get; set; } = string.Empty;
        /// <summary>Windows workstation hostname displayed in the Mac Touch ID prompt.</summary>
        [JsonPropertyName("requester_hostname")] public string RequesterHostname { get; set; } = Environment.MachineName;
    }

    /// <summary>Response DTO returned from Rust core for passkey creation.</summary>
    internal sealed class RemotePasskeyMakeCredResponseData
    {
        /// <summary>Hex-encoded newly generated credential identifier.</summary>
        [JsonPropertyName("credential_id_hex")] public string CredentialIdHex { get; set; } = string.Empty;
        /// <summary>Hex-encoded WebAuthn authenticatorData bytes.</summary>
        [JsonPropertyName("auth_data_hex")] public string AuthDataHex { get; set; } = string.Empty;
        /// <summary>WebAuthn attestation statement format (default "none").</summary>
        [JsonPropertyName("attestation_format")] public string AttestationFormat { get; set; } = "none";
        /// <summary>Optional hex-encoded CBOR attestation object bytes.</summary>
        [JsonPropertyName("attestation_object_cbor_hex")] public string AttestationObjectCborHex { get; set; } = string.Empty;
    }

    /// <summary>Request DTO dispatched to Rust core to invoke remote Mac passkey assertion.</summary>
    internal sealed class RemotePasskeyGetAssertionDto
    {
        /// <summary>Optional target Mac peer IP override (null auto-selects best paired Mac).</summary>
        [JsonPropertyName("peer_ip")] public string? PeerIp { get; set; }
        /// <summary>GetAssertion request payload forwarded to macOS Secure Enclave.</summary>
        [JsonPropertyName("request")] public RemotePasskeyGetAssertRequestData Request { get; set; } = new();
    }

    /// <summary>GetAssertion inner request parameters.</summary>
    internal sealed class RemotePasskeyGetAssertRequestData
    {
        /// <summary>Hex-encoded 32-byte SHA-256 clientDataJSON hash.</summary>
        [JsonPropertyName("client_data_hash_hex")] public string ClientDataHashHex { get; set; } = string.Empty;
        /// <summary>Relying Party domain identifier.</summary>
        [JsonPropertyName("rp_id")] public string RpId { get; set; } = string.Empty;
        /// <summary>Hex-encoded list of allowed credential IDs (empty for discoverable passkeys).</summary>
        [JsonPropertyName("allow_credential_ids_hex")] public List<string> AllowCredentialIdsHex { get; set; } = new();
        /// <summary>Windows workstation hostname displayed in the Mac Touch ID prompt.</summary>
        [JsonPropertyName("requester_hostname")] public string RequesterHostname { get; set; } = Environment.MachineName;
    }

    /// <summary>Response DTO returned from Rust core for passkey assertion.</summary>
    internal sealed class RemotePasskeyGetAssertResponseData
    {
        /// <summary>Hex-encoded credential identifier that signed the assertion.</summary>
        [JsonPropertyName("credential_id_hex")] public string CredentialIdHex { get; set; } = string.Empty;
        /// <summary>Hex-encoded user handle associated with the matched resident passkey.</summary>
        [JsonPropertyName("user_id_hex")] public string UserIdHex { get; set; } = string.Empty;
        /// <summary>Hex-encoded WebAuthn authenticatorData bytes.</summary>
        [JsonPropertyName("auth_data_hex")] public string AuthDataHex { get; set; } = string.Empty;
        /// <summary>Hex-encoded ASN.1 DER ECDSA P-256 assertion signature.</summary>
        [JsonPropertyName("signature_der_hex")] public string SignatureDerHex { get; set; } = string.Empty;
        /// <summary>Monotonic authenticator signature counter value.</summary>
        [JsonPropertyName("sign_count")] public uint SignCount { get; set; }
    }

    // ==========================================================================================
    // Passkey Authenticator Plugin Implementation
    // ==========================================================================================

    /// <summary>
    /// Singleton manager and COM Class Factory for the Integrator Passkey Provider plugin.
    /// Registers with Windows WebAuthn APIs and routes cryptographic operations to macOS Touch ID.
    /// </summary>
    internal sealed class PasskeyAuthenticatorPlugin : IPluginAuthenticator, IClassFactory
    {
        // --------------------------------------------------------------------------------------
        // Protocol Constants & Magic Numbers (Strictly Zero Inline Literals)
        // --------------------------------------------------------------------------------------

        /// <summary>CLSID string for Integrator Passkey Provider COM object.</summary>
        public const string CLSID_IntegratorPasskeyAuthenticator_String = "4b2c1f30-8a1e-4509-913a-96696ef07bc3";

        /// <summary>IID string for IPluginAuthenticator COM interface.</summary>
        public const string IID_IPluginAuthenticator_String = "d26bcf6f-b54c-43ff-9f06-d5bf148625f7";

        /// <summary>CLSID GUID instance.</summary>
        public static readonly Guid CLSID_IntegratorPasskeyAuthenticator = new(CLSID_IntegratorPasskeyAuthenticator_String);

        /// <summary>IID GUID instance for IPluginAuthenticator.</summary>
        public static readonly Guid IID_IPluginAuthenticator = new(IID_IPluginAuthenticator_String);

        /// <summary>IID GUID instance for IUnknown.</summary>
        public static readonly Guid IID_IUnknown = new("00000000-0000-0000-C000-000000000046");

        /// <summary>COM CLSCTX_LOCAL_SERVER flag indicating out-of-process COM execution.</summary>
        private const uint CLSCTX_LOCAL_SERVER = 0x04u;

        /// <summary>COM REGCLS_MULTIPLEUSE flag permitting multiple client connections to the class object.</summary>
        private const uint REGCLS_MULTIPLEUSE = 0x01u;

        /// <summary>Standard COM S_OK status code.</summary>
        private const int S_OK = 0;

        /// <summary>Standard COM E_FAIL status code.</summary>
        private const int E_FAIL = unchecked((int)0x80004005);

        /// <summary>Standard COM E_INVALIDARG status code.</summary>
        private const int E_INVALIDARG = unchecked((int)0x80070057);

        /// <summary>Standard COM E_NOINTERFACE status code.</summary>
        private const int E_NOINTERFACE = unchecked((int)0x80004002);

        /// <summary>Standard COM CLASS_E_NOAGGREGATION status code.</summary>
        private const int CLASS_E_NOAGGREGATION = unchecked((int)0x80040110);

        /// <summary>Win32 error code indicating entity already exists.</summary>
        private const int NTE_EXISTS = unchecked((int)0x8009000F);

        /// <summary>Win32 error code indicating user canceled biometric verification.</summary>
        private const int NTE_USER_CANCELLED = unchecked((int)0x80090036);

        /// <summary>Vault lock status: unlocked (1).</summary>
        private const int PLUGIN_LOCK_STATUS_UNLOCKED = 1;

        /// <summary>Current version constant for WEBAUTHN_CREDENTIAL_ATTESTATION.</summary>
        private const uint WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION = 1u;

        /// <summary>Current version constant for WEBAUTHN_CREDENTIAL_DETAILS.</summary>
        private const uint WEBAUTHN_CREDENTIAL_DETAILS_CURRENT_VERSION = 1u;

        /// <summary>Current version constant for WEBAUTHN_ASSERTION.</summary>
        private const uint WEBAUTHN_ASSERTION_CURRENT_VERSION = 1u;

        /// <summary>Maximum allowed byte length (4096 bytes) for decoded native WebAuthn byte fields.</summary>
        private const uint MaxNativeFieldBytes = 4096u;

        /// <summary>Maximum allowed number of credential descriptors (256) read from an allowList.</summary>
        private const uint MaxAllowCredentialCount = 256u;

        /// <summary>Canonical attestation format name for zero/self attestation.</summary>
        private const string WEBAUTHN_ATTESTATION_TYPE_NONE = "none";

        /// <summary>Canonical authenticator name presented in Windows Passkey settings.</summary>
        private const string AUTHENTICATOR_DISPLAY_NAME = "Integrator Touch ID";

        /// <summary>Canonical plugin relying party domain identifier.</summary>
        private const string PLUGIN_RP_ID = "integrator.local";

        // --------------------------------------------------------------------------------------
        // Win32 API P/Invoke Imports (System32-pinned to prevent DLL search-order hijacking)
        // --------------------------------------------------------------------------------------

        /// <summary>Registers an out-of-process COM class object with the Windows SCM.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("ole32.dll")]
        private static extern int CoRegisterClassObject(
            ref Guid rclsid,
            [MarshalAs(UnmanagedType.IUnknown)] object pUnk,
            uint dwClsContext,
            uint flags,
            out uint lpdwRegister);

        /// <summary>Revokes a previously registered COM class object cookie.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("ole32.dll")]
        private static extern int CoRevokeClassObject(uint dwRegister);

        /// <summary>Registers the plugin authenticator metadata and CBOR capabilities with Windows WebAuthn.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("webauthn.dll", CharSet = CharSet.Unicode)]
        private static extern int WebAuthNPluginAddAuthenticator2(
            ref WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS_2 options,
            out IntPtr response);

        /// <summary>Frees the response buffer allocated by <see cref="WebAuthNPluginAddAuthenticator2"/>.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("webauthn.dll")]
        private static extern void WebAuthNPluginFreeAddAuthenticatorResponse(IntPtr response);

        /// <summary>Queries the current enabled/disabled state of a registered WebAuthn plugin authenticator.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("webauthn.dll")]
        private static extern int WebAuthNPluginGetAuthenticatorState(ref Guid rclsid, out int state);

        /// <summary>Decodes an incoming CTAP2 CBOR MakeCredential request into a structured native descriptor.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("webauthn.dll", CharSet = CharSet.Unicode)]
        private static extern int WebAuthNDecodeMakeCredentialRequest(
            uint cbEncoded,
            IntPtr pbEncoded,
            out IntPtr ppMakeCredentialRequest);

        /// <summary>Frees a decoded MakeCredential request structure returned by <see cref="WebAuthNDecodeMakeCredentialRequest"/>.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("webauthn.dll")]
        private static extern void WebAuthNFreeDecodedMakeCredentialRequest(IntPtr pMakeCredentialRequest);

        /// <summary>Encodes a WebAuthn attestation structure into a CTAP2 CBOR MakeCredential response buffer.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("webauthn.dll", CharSet = CharSet.Unicode)]
        private static extern int WebAuthNEncodeMakeCredentialResponse(
            ref WEBAUTHN_CREDENTIAL_ATTESTATION pCredentialAttestation,
            out uint pcbResp,
            out IntPtr ppbResp);

        /// <summary>Decodes an incoming CTAP2 CBOR GetAssertion request into a structured native descriptor.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("webauthn.dll", CharSet = CharSet.Unicode)]
        private static extern int WebAuthNDecodeGetAssertionRequest(
            uint cbEncoded,
            IntPtr pbEncoded,
            out IntPtr ppGetAssertionRequest);

        /// <summary>Frees a decoded GetAssertion request structure returned by <see cref="WebAuthNDecodeGetAssertionRequest"/>.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("webauthn.dll")]
        private static extern void WebAuthNFreeDecodedGetAssertionRequest(IntPtr pGetAssertionRequest);

        /// <summary>Encodes a WebAuthn assertion response structure into a CTAP2 CBOR GetAssertion response buffer.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("webauthn.dll")]
        private static extern int WebAuthNEncodeGetAssertionResponse(
            ref EXPERIMENTAL_WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE pGetAssertionResponse,
            out uint pcbResp,
            out IntPtr ppbResp);

        /// <summary>Registers resident passkey metadata in the Windows Credential Manager autofill cache.</summary>
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("webauthn.dll")]
        private static extern int WebAuthNPluginAuthenticatorAddCredentials(
            ref Guid rclsid,
            uint cCredentialDetails,
            IntPtr pCredentialDetails);

        // --------------------------------------------------------------------------------------
        // Singleton State & Registration Cookies
        // --------------------------------------------------------------------------------------

        /// <summary>Mutex protecting initialization, COM registration cookie updates, and teardown.</summary>
        private static readonly object _syncLock = new();
        /// <summary>Singleton COM factory/authenticator instance.</summary>
        private static PasskeyAuthenticatorPlugin? _instance;
        /// <summary>Active COM class registration cookie returned by <see cref="CoRegisterClassObject"/>.</summary>
        private static uint _classRegistrationCookie;
        /// <summary>Volatile flag tracking whether Windows WebAuthn reports the plugin as registered and enabled.</summary>
        private static volatile bool _isRegisteredWithWindows;

        /// <summary>Private lock serializing concurrent WebAuthn operations.</summary>
        private readonly object _operationLock = new();

        /// <summary>Returns true if the plugin authenticator is initialized and registered.</summary>
        public static bool IsActive => _isRegisteredWithWindows && Volatile.Read(ref _classRegistrationCookie) != 0;

        /// <summary>
        /// Queries Windows 11 WebAuthn subsystem to verify if Integrator Passkey Provider is registered.
        /// </summary>
        public static bool IsRegistered
        {
            get
            {
                if (_isRegisteredWithWindows) return true;
                try
                {
                    Guid clsid = CLSID_IntegratorPasskeyAuthenticator;
                    int hr = WebAuthNPluginGetAuthenticatorState(ref clsid, out int state);
                    if (hr == S_OK && state == 1)
                    {
                        _isRegisteredWithWindows = true;
                        return true;
                    }
                }
                catch { }
                return false;
            }
        }

        // ======================================================================================
        // Initialization & Teardown Lifecycle
        // ======================================================================================

        /// <summary>
        /// Registers the COM Class Factory and ensures the plugin authenticator is active with Windows.
        /// Safe to call multiple times idempotently.
        /// </summary>
        public static void Initialize()
        {
            lock (_syncLock)
            {
                if (_instance != null)
                {
                    return;
                }

                _instance = new PasskeyAuthenticatorPlugin();

                // 1. Register COM Class Object with Windows Local Server table
                Guid clsid = CLSID_IntegratorPasskeyAuthenticator;
                int hrCo = CoRegisterClassObject(
                    ref clsid,
                    _instance,
                    CLSCTX_LOCAL_SERVER,
                    REGCLS_MULTIPLEUSE,
                    out _classRegistrationCookie);

                if (hrCo != S_OK)
                {
                    System.Diagnostics.Debug.WriteLine($"[PasskeyPlugin] CoRegisterClassObject failed: 0x{hrCo:X8}");
                }
                else
                {
                    System.Diagnostics.Debug.WriteLine($"[PasskeyPlugin] COM class registered cookie={_classRegistrationCookie}");
                }

                // 2. Register / Verify Passkey Authenticator with Windows 11 WebAuthn Subsystem
                RegisterWithWindowsSubsystem();
            }
        }

        /// <summary>
        /// Revokes the COM Class Object and cleans up plugin registration.
        /// Safe to invoke repeatedly or during partial initialization.
        /// </summary>
        public static void Shutdown()
        {
            lock (_syncLock)
            {
                uint cookie = Interlocked.Exchange(ref _classRegistrationCookie, 0u);
                if (cookie != 0)
                {
                    try { CoRevokeClassObject(cookie); } catch { }
                }
                _instance = null;
            }
        }

        /// <summary>
        /// Appends a diagnostic log entry to <c>%USERPROFILE%\.integrator_passkey.log</c> without throwing.
        /// </summary>
        /// <param name="message">Formatted diagnostic line including timestamp.</param>
        private static void AppendDiagnosticLog(string message)
        {
            System.Diagnostics.Debug.WriteLine(message);
            try
            {
                string logPath = System.IO.Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                    ".integrator_passkey.log");
                System.IO.File.AppendAllText(logPath, message);
            }
            catch { }
        }

        /// <summary>
        /// Registers the authenticator options with Windows 11 WebAuthNPluginAddAuthenticator2.
        /// </summary>
        private static void RegisterWithWindowsSubsystem()
        {
            IntPtr pClsid = IntPtr.Zero;
            IntPtr pCbor = IntPtr.Zero;
            IntPtr pResp = IntPtr.Zero;
            try
            {
                // Canonical CTAP2 getInfo CBOR bytes:
                // Map: { 1: ["FIDO_2_0"], 3: 16-byte AAGUID, 4: {"rk": true, "up": true, "uv": true} }
                byte[] cborInfo = new byte[] {
                    0xa3,
                    0x01, 0x81, 0x68, 0x46, 0x49, 0x44, 0x4f, 0x5f, 0x32, 0x5f, 0x30,
                    0x03, 0x50, 0xd9, 0xa4, 0xa4, 0xe1, 0x2f, 0xbc, 0x4b, 0x57, 0x90, 0x8d, 0xa2, 0x47, 0xe1, 0x68, 0x06, 0xf4,
                    0x04, 0xa3, 0x62, 0x72, 0x6b, 0xf5, 0x62, 0x75, 0x70, 0xf5, 0x62, 0x75, 0x76, 0xf5
                };

                Guid clsid = CLSID_IntegratorPasskeyAuthenticator;
                pClsid = Marshal.AllocHGlobal(Marshal.SizeOf<Guid>());
                Marshal.StructureToPtr(clsid, pClsid, false);

                pCbor = Marshal.AllocHGlobal(cborInfo.Length);
                Marshal.Copy(cborInfo, 0, pCbor, cborInfo.Length);

                var opts = new WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS_2
                {
                    pwszAuthenticatorName = AUTHENTICATOR_DISPLAY_NAME,
                    pClsid = pClsid,
                    pwszPluginRpId = PLUGIN_RP_ID,
                    cbAuthenticatorInfo = (uint)cborInfo.Length,
                    pbAuthenticatorInfo = pCbor,
                    cSupportedRpIds = 0,
                    ppwszSupportedRpIds = IntPtr.Zero
                };

                int hr = WebAuthNPluginAddAuthenticator2(ref opts, out pResp);
                if (hr == S_OK || hr == NTE_EXISTS)
                {
                    _isRegisteredWithWindows = true;
                    AppendDiagnosticLog($"[{DateTime.UtcNow:O}] [PasskeyPlugin] WebAuthn plugin registered successfully (HR=0x{hr:X8})\r\n");
                }
                else
                {
                    AppendDiagnosticLog($"[{DateTime.UtcNow:O}] [PasskeyPlugin] WebAuthn plugin registration warning HR=0x{hr:X8}\r\n");
                }
            }
            catch (Exception ex)
            {
                AppendDiagnosticLog($"[{DateTime.UtcNow:O}] [PasskeyPlugin] Exception during registration: {ex}\r\n");
            }
            finally
            {
                if (pResp != IntPtr.Zero) WebAuthNPluginFreeAddAuthenticatorResponse(pResp);
                if (pCbor != IntPtr.Zero) Marshal.FreeHGlobal(pCbor);
                if (pClsid != IntPtr.Zero) Marshal.FreeHGlobal(pClsid);
            }
        }

        // ======================================================================================
        // IClassFactory Implementation
        // ======================================================================================

        /// <summary>Creates and returns the requested COM interface pointer for this singleton authenticator.</summary>
        int IClassFactory.CreateInstance(IntPtr pUnkOuter, ref Guid riid, out IntPtr ppvObject)
        {
            ppvObject = IntPtr.Zero;

            // Aggregation is not supported for plugin authenticators
            if (pUnkOuter != IntPtr.Zero)
            {
                return CLASS_E_NOAGGREGATION;
            }

            // Query for IPluginAuthenticator or IUnknown
            if (riid == IID_IPluginAuthenticator || riid == IID_IUnknown)
            {
                ppvObject = Marshal.GetComInterfaceForObject(this, typeof(IPluginAuthenticator));
                return S_OK;
            }

            return E_NOINTERFACE;
        }

        /// <summary>Implements <c>IClassFactory::LockServer</c> (no-op for process-lifetime singleton).</summary>
        int IClassFactory.LockServer(bool fLock)
        {
            return S_OK;
        }

        // ======================================================================================
        // IPluginAuthenticator Implementation
        // ======================================================================================

        /// <inheritdoc />
        public int GetLockStatus(out int lockStatus)
        {
            // The Integrator Passkey provider is always unlocked because authentication
            // is delegated interactively to physical Apple Touch ID hardware.
            lockStatus = PLUGIN_LOCK_STATUS_UNLOCKED;
            return S_OK;
        }

        /// <inheritdoc />
        public int CancelOperation(in WEBAUTHN_PLUGIN_CANCEL_OPERATION_REQUEST request)
        {
            // Windows signaled cancellation (e.g. user dismissed browser dialog).
            System.Diagnostics.Debug.WriteLine($"[PasskeyPlugin] Operation cancelled for tx={request.transactionId}");
            return S_OK;
        }

        /// <inheritdoc />
        public int MakeCredential(
            in WEBAUTHN_PLUGIN_OPERATION_REQUEST request,
            out WEBAUTHN_PLUGIN_OPERATION_RESPONSE response)
        {
            response = default;

            if (request.cbEncodedRequest == 0 || request.pbEncodedRequest == IntPtr.Zero)
            {
                return E_INVALIDARG;
            }

            lock (_operationLock)
            {
                IntPtr pDecoded = IntPtr.Zero;
                IntPtr pAuthData = IntPtr.Zero;
                IntPtr pCredId = IntPtr.Zero;
                IntPtr pDetails = IntPtr.Zero;
                try
                {
                    // 1. Decode incoming CTAP2 CBOR MakeCredential request using Windows native API
                    int hrDecode = WebAuthNDecodeMakeCredentialRequest(
                        request.cbEncodedRequest,
                        request.pbEncodedRequest,
                        out pDecoded);

                    if (hrDecode != S_OK || pDecoded == IntPtr.Zero)
                    {
                        System.Diagnostics.Debug.WriteLine($"[PasskeyPlugin] DecodeMakeCredential failed: 0x{hrDecode:X8}");
                        return hrDecode != S_OK ? hrDecode : E_FAIL;
                    }

                    var decoded = Marshal.PtrToStructure<EXPERIMENTAL_WEBAUTHN_CTAPCBOR_MAKE_CREDENTIAL_REQUEST>(pDecoded);

                    // 2. Extract Relying Party domain
                    string rpId = string.Empty;
                    if (decoded.pRpInformation != IntPtr.Zero)
                    {
                        var rp = Marshal.PtrToStructure<WEBAUTHN_RP_ENTITY_INFORMATION>(decoded.pRpInformation);
                        rpId = rp.pwszId ?? string.Empty;
                    }
                    if (string.IsNullOrEmpty(rpId) && decoded.cbRpId > 0 && decoded.cbRpId <= MaxNativeFieldBytes && decoded.pbRpId != IntPtr.Zero)
                    {
                        byte[] rpBytes = new byte[decoded.cbRpId];
                        Marshal.Copy(decoded.pbRpId, rpBytes, 0, (int)decoded.cbRpId);
                        rpId = System.Text.Encoding.UTF8.GetString(rpBytes);
                    }

                    // 3. Extract Client Data Hash (32 bytes, bounded for safety)
                    uint cdhLen = decoded.cbClientDataHash <= MaxNativeFieldBytes ? decoded.cbClientDataHash : 0u;
                    byte[] cdhBytes = new byte[cdhLen];
                    if (decoded.pbClientDataHash != IntPtr.Zero && cdhLen > 0)
                    {
                        Marshal.Copy(decoded.pbClientDataHash, cdhBytes, 0, (int)cdhLen);
                    }
                    string clientDataHashHex = Convert.ToHexString(cdhBytes).ToLowerInvariant();

                    // 4. Extract User Entity Information
                    string userName = "user";
                    string userDisplayName = "User";
                    string userIdHex = "00";
                    if (decoded.pUserInformation != IntPtr.Zero)
                    {
                        var user = Marshal.PtrToStructure<WEBAUTHN_USER_ENTITY_INFORMATION>(decoded.pUserInformation);
                        userName = user.pwszName ?? "user";
                        userDisplayName = user.pwszDisplayName ?? userName;
                        if (user.cbId > 0 && user.cbId <= MaxNativeFieldBytes && user.pbId != IntPtr.Zero)
                        {
                            byte[] uBytes = new byte[user.cbId];
                            Marshal.Copy(user.pbId, uBytes, 0, (int)user.cbId);
                            userIdHex = Convert.ToHexString(uBytes).ToLowerInvariant();
                        }
                    }

                    // 5. Construct remote RPC payload for macOS Touch ID evaluation
                    var rpcPayload = new RemotePasskeyMakeCredentialDto
                    {
                        PeerIp = null, // Auto-resolve best paired Mac
                        Request = new RemotePasskeyMakeCredRequestData
                        {
                            RpId = rpId,
                            ClientDataHashHex = clientDataHashHex,
                            UserIdHex = userIdHex,
                            UserName = userName,
                            UserDisplayName = userDisplayName,
                            RequesterHostname = Environment.MachineName
                        }
                    };

                    // 6. Invoke remote passkey creation via TransportSessionV2
                    var rpcResult = CoreBridge.Invoke<RemotePasskeyMakeCredResponseData>(
                        "passkey_make_credential_remote",
                        rpcPayload);

                    if (!rpcResult.Ok || rpcResult.Data == null ||
                        string.IsNullOrEmpty(rpcResult.Data.AuthDataHex) ||
                        string.IsNullOrEmpty(rpcResult.Data.CredentialIdHex))
                    {
                        return NTE_USER_CANCELLED;
                    }

                    var respDto = rpcResult.Data;

                    // 7. Parse authenticatorData and credential ID returned by Mac
                    byte[] authDataBytes = Convert.FromHexString(respDto.AuthDataHex);
                    byte[] credIdBytes = Convert.FromHexString(respDto.CredentialIdHex);
                    if (authDataBytes.Length == 0 || credIdBytes.Length == 0)
                    {
                        return NTE_USER_CANCELLED;
                    }

                    pAuthData = Marshal.AllocHGlobal(authDataBytes.Length);
                    Marshal.Copy(authDataBytes, 0, pAuthData, authDataBytes.Length);

                    pCredId = Marshal.AllocHGlobal(credIdBytes.Length);
                    Marshal.Copy(credIdBytes, 0, pCredId, credIdBytes.Length);

                    // 8. Construct WEBAUTHN_CREDENTIAL_ATTESTATION for Windows encoding
                    var att = new WEBAUTHN_CREDENTIAL_ATTESTATION
                    {
                        dwVersion = WEBAUTHN_CREDENTIAL_ATTESTATION_CURRENT_VERSION,
                        pwszFormatType = WEBAUTHN_ATTESTATION_TYPE_NONE,
                        cbAuthenticatorData = (uint)authDataBytes.Length,
                        pbAuthenticatorData = pAuthData,
                        cbAttestation = 0,
                        pbAttestation = IntPtr.Zero,
                        cbAttestationObject = 0,
                        pbAttestationObject = IntPtr.Zero,
                        cbCredentialId = (uint)credIdBytes.Length,
                        pbCredentialId = pCredId,
                        CredentialEx = new WEBAUTHN_CREDENTIAL_EX
                        {
                            dwVersion = 1,
                            cbId = (uint)credIdBytes.Length,
                            pbId = pCredId,
                            pwszCredentialType = "public-key",
                            dwTransports = 0
                        }
                    };

                    int hrEncode = WebAuthNEncodeMakeCredentialResponse(
                        ref att,
                        out uint cbResp,
                        out IntPtr pbResp);

                    if (hrEncode != S_OK || pbResp == IntPtr.Zero)
                    {
                        System.Diagnostics.Debug.WriteLine($"[PasskeyPlugin] EncodeMakeCredential failed: 0x{hrEncode:X8}");
                        return hrEncode != S_OK ? hrEncode : E_FAIL;
                    }

                    // 9. Assign response buffer (Windows caller reclaims with CoTaskMemFree)
                    response.cbEncodedResponse = cbResp;
                    response.pbEncodedResponse = pbResp;

                    // 10. Register passkey metadata with Windows Credential Manager cache
                    try
                    {
                        var credDetails = new WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS
                        {
                            dwVersion = WEBAUTHN_CREDENTIAL_DETAILS_CURRENT_VERSION,
                            pUserInformation = decoded.pUserInformation,
                            pRpInformation = decoded.pRpInformation,
                            cbCredentialID = (uint)credIdBytes.Length,
                            pbCredentialID = pCredId,
                            cbRemovableStorageID = 0,
                            pbRemovableStorageID = IntPtr.Zero,
                            bBackedUp = true
                        };

                        pDetails = Marshal.AllocHGlobal(Marshal.SizeOf<WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS>());
                        Marshal.StructureToPtr(credDetails, pDetails, false);
                        Guid clsid = CLSID_IntegratorPasskeyAuthenticator;
                        WebAuthNPluginAuthenticatorAddCredentials(ref clsid, 1, pDetails);
                    }
                    catch { }

                    return S_OK;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[PasskeyPlugin] MakeCredential exception: {ex}");
                    return E_FAIL;
                }
                finally
                {
                    if (pDetails != IntPtr.Zero)
                    {
                        Marshal.DestroyStructure<WEBAUTHN_PLUGIN_CREDENTIAL_DETAILS>(pDetails);
                        Marshal.FreeHGlobal(pDetails);
                    }
                    if (pCredId != IntPtr.Zero) Marshal.FreeHGlobal(pCredId);
                    if (pAuthData != IntPtr.Zero) Marshal.FreeHGlobal(pAuthData);
                    if (pDecoded != IntPtr.Zero) WebAuthNFreeDecodedMakeCredentialRequest(pDecoded);
                }
            }
        }

        /// <inheritdoc />
        public int GetAssertion(
            in WEBAUTHN_PLUGIN_OPERATION_REQUEST request,
            out WEBAUTHN_PLUGIN_OPERATION_RESPONSE response)
        {
            response = default;

            if (request.cbEncodedRequest == 0 || request.pbEncodedRequest == IntPtr.Zero)
            {
                return E_INVALIDARG;
            }

            lock (_operationLock)
            {
                IntPtr pDecoded = IntPtr.Zero;
                IntPtr pAuthData = IntPtr.Zero;
                IntPtr pSig = IntPtr.Zero;
                IntPtr pCredId = IntPtr.Zero;
                IntPtr pUserId = IntPtr.Zero;
                try
                {
                    // 1. Decode incoming CTAP2 CBOR GetAssertion request using Windows native API
                    int hrDecode = WebAuthNDecodeGetAssertionRequest(
                        request.cbEncodedRequest,
                        request.pbEncodedRequest,
                        out pDecoded);

                    if (hrDecode != S_OK || pDecoded == IntPtr.Zero)
                    {
                        System.Diagnostics.Debug.WriteLine($"[PasskeyPlugin] DecodeGetAssertion failed: 0x{hrDecode:X8}");
                        return hrDecode != S_OK ? hrDecode : E_FAIL;
                    }

                    var decoded = Marshal.PtrToStructure<EXPERIMENTAL_WEBAUTHN_CTAPCBOR_GET_ASSERTION_REQUEST>(pDecoded);

                    // 2. Extract Relying Party domain
                    string rpId = decoded.pwszRpId ?? string.Empty;
                    if (string.IsNullOrEmpty(rpId) && decoded.cbRpId > 0 && decoded.cbRpId <= MaxNativeFieldBytes && decoded.pbRpId != IntPtr.Zero)
                    {
                        byte[] rpBytes = new byte[decoded.cbRpId];
                        Marshal.Copy(decoded.pbRpId, rpBytes, 0, (int)decoded.cbRpId);
                        rpId = System.Text.Encoding.UTF8.GetString(rpBytes);
                    }

                    // 3. Extract Client Data Hash (32 bytes, bounded for safety)
                    uint cdhLen = decoded.cbClientDataHash <= MaxNativeFieldBytes ? decoded.cbClientDataHash : 0u;
                    byte[] cdhBytes = new byte[cdhLen];
                    if (decoded.pbClientDataHash != IntPtr.Zero && cdhLen > 0)
                    {
                        Marshal.Copy(decoded.pbClientDataHash, cdhBytes, 0, (int)cdhLen);
                    }
                    string clientDataHashHex = Convert.ToHexString(cdhBytes).ToLowerInvariant();

                    // 4. Extract allowed credential descriptors (bounded by MaxAllowCredentialCount)
                    var allowList = new List<string>();
                    if (decoded.CredentialList.cCredentials > 0 && decoded.CredentialList.ppCredentials != IntPtr.Zero)
                    {
                        int ptrSize = IntPtr.Size;
                        uint allowCount = Math.Min(decoded.CredentialList.cCredentials, MaxAllowCredentialCount);
                        for (int i = 0; i < allowCount; i++)
                        {
                            IntPtr credPtr = Marshal.ReadIntPtr(decoded.CredentialList.ppCredentials, i * ptrSize);
                            if (credPtr != IntPtr.Zero)
                            {
                                var cred = Marshal.PtrToStructure<WEBAUTHN_CREDENTIAL_EX>(credPtr);
                                if (cred.cbId > 0 && cred.cbId <= MaxNativeFieldBytes && cred.pbId != IntPtr.Zero)
                                {
                                    byte[] idBytes = new byte[cred.cbId];
                                    Marshal.Copy(cred.pbId, idBytes, 0, (int)cred.cbId);
                                    allowList.Add(Convert.ToHexString(idBytes).ToLowerInvariant());
                                }
                            }
                        }
                    }

                    // 5. Construct remote RPC payload for macOS Touch ID evaluation
                    var rpcPayload = new RemotePasskeyGetAssertionDto
                    {
                        PeerIp = null, // Auto-resolve best paired Mac
                        Request = new RemotePasskeyGetAssertRequestData
                        {
                            RpId = rpId,
                            ClientDataHashHex = clientDataHashHex,
                            AllowCredentialIdsHex = allowList,
                            RequesterHostname = Environment.MachineName
                        }
                    };

                    // 6. Invoke remote passkey assertion via TransportSessionV2
                    var rpcResult = CoreBridge.Invoke<RemotePasskeyGetAssertResponseData>(
                        "passkey_get_assertion_remote",
                        rpcPayload);

                    if (!rpcResult.Ok || rpcResult.Data == null ||
                        string.IsNullOrEmpty(rpcResult.Data.SignatureDerHex) ||
                        string.IsNullOrEmpty(rpcResult.Data.AuthDataHex) ||
                        string.IsNullOrEmpty(rpcResult.Data.CredentialIdHex))
                    {
                        return NTE_USER_CANCELLED;
                    }

                    var respDto = rpcResult.Data;

                    // 7. Parse assertion payload returned by Mac
                    byte[] authDataBytes = Convert.FromHexString(respDto.AuthDataHex);
                    byte[] sigBytes = Convert.FromHexString(respDto.SignatureDerHex);
                    byte[] credIdBytes = Convert.FromHexString(respDto.CredentialIdHex);
                    byte[] userIdBytes = string.IsNullOrEmpty(respDto.UserIdHex)
                        ? Array.Empty<byte>()
                        : Convert.FromHexString(respDto.UserIdHex);
                    if (authDataBytes.Length == 0 || sigBytes.Length == 0 || credIdBytes.Length == 0)
                    {
                        return NTE_USER_CANCELLED;
                    }

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
                    }

                    // 8. Construct EXPERIMENTAL_WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE for Windows encoding
                    var assertResp = new EXPERIMENTAL_WEBAUTHN_CTAPCBOR_GET_ASSERTION_RESPONSE
                    {
                        WebAuthNAssertion = new WEBAUTHN_ASSERTION
                        {
                            dwVersion = WEBAUTHN_ASSERTION_CURRENT_VERSION,
                            cbAuthenticatorData = (uint)authDataBytes.Length,
                            pbAuthenticatorData = pAuthData,
                            cbSignature = (uint)sigBytes.Length,
                            pbSignature = pSig,
                            Credential = new WEBAUTHN_CREDENTIAL_EX
                            {
                                dwVersion = 1,
                                cbId = (uint)credIdBytes.Length,
                                pbId = pCredId,
                                pwszCredentialType = "public-key",
                                dwTransports = 0
                            },
                            cbUserId = (uint)userIdBytes.Length,
                            pbUserId = pUserId
                        },
                        pUserInformation = IntPtr.Zero,
                        dwNumberOfCredentials = 1,
                        lUserSelected = 0,
                        cbLargeBlobKey = 0,
                        pbLargeBlobKey = IntPtr.Zero,
                        cbUnsignedExtensionOutputs = 0,
                        pbUnsignedExtensionOutputs = IntPtr.Zero
                    };

                    int hrEncode = WebAuthNEncodeGetAssertionResponse(
                        ref assertResp,
                        out uint cbResp,
                        out IntPtr pbResp);

                    if (hrEncode != S_OK || pbResp == IntPtr.Zero)
                    {
                        System.Diagnostics.Debug.WriteLine($"[PasskeyPlugin] EncodeGetAssertion failed: 0x{hrEncode:X8}");
                        return hrEncode != S_OK ? hrEncode : E_FAIL;
                    }

                    // 9. Assign response buffer (Windows caller reclaims with CoTaskMemFree)
                    response.cbEncodedResponse = cbResp;
                    response.pbEncodedResponse = pbResp;

                    return S_OK;
                }
                catch (Exception ex)
                {
                    System.Diagnostics.Debug.WriteLine($"[PasskeyPlugin] GetAssertion exception: {ex}");
                    return E_FAIL;
                }
                finally
                {
                    if (pUserId != IntPtr.Zero) Marshal.FreeHGlobal(pUserId);
                    if (pCredId != IntPtr.Zero) Marshal.FreeHGlobal(pCredId);
                    if (pSig != IntPtr.Zero) Marshal.FreeHGlobal(pSig);
                    if (pAuthData != IntPtr.Zero) Marshal.FreeHGlobal(pAuthData);
                    if (pDecoded != IntPtr.Zero) WebAuthNFreeDecodedGetAssertionRequest(pDecoded);
                }
            }
        }
    }
}
