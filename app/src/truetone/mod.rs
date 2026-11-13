//! Cross-Screen True Tone & Chromatic Adaptation Sync.
//!
//! Matches Windows OMEN screen white point to MacBook Pro Retina display
//! in real-time using ambient light sensor telemetry and Bradford CAT.

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmbientLightData {
    pub lux: f32,
    pub cct_kelvin: u32,
    pub supported: bool,
    pub updated_at_secs: u64,
}

#[cfg(target_os = "macos")]
extern "C" {
    fn read_mac_ambient_sensor(out_lux: *mut f32, out_cct: *mut u32) -> bool;
}

/// Reads the local machine ambient light sensor if available.
pub fn read_ambient_light() -> AmbientLightData {
    #[cfg(target_os = "macos")]
    {
        let mut lux: f32 = 0.0;
        let mut cct: u32 = 0;
        let ok = unsafe { read_mac_ambient_sensor(&mut lux, &mut cct) };
        if ok {
            AmbientLightData {
                lux,
                cct_kelvin: cct,
                supported: true,
                updated_at_secs: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            }
        } else {
            AmbientLightData {
                lux: 100.0,
                cct_kelvin: 5500,
                supported: false,
                updated_at_secs: 0,
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        AmbientLightData {
            lux: 0.0,
            cct_kelvin: 6500,
            supported: false,
            updated_at_secs: 0,
        }
    }
}

/// Calculates Bradford Chromatic Adaptation Transform RGB scaling factors
/// for target ambient CCT (Kelvin) relative to standard D65 (6500K) white point.
#[allow(dead_code)]
pub fn calculate_bradford_multipliers(cct_kelvin: u32, gamma_comp: f32) -> (f32, f32, f32) {
    let t = (cct_kelvin.max(2500).min(9000)) as f32;

    // Approximate CIE 1931 chromaticity coordinates (x, y) from CCT Kelvin
    let (x, y) = if t <= 4000.0 {
        let inv_t = 1000.0 / t;
        let x = -0.2661239 * inv_t.powi(3) - 0.2343580 * inv_t.powi(2) + 0.8776956 * inv_t + 0.179910;
        let y = -1.1063814 * x.powi(3) - 1.34811020 * x.powi(2) + 2.18555832 * x - 0.20219683;
        (x, y)
    } else {
        let inv_t = 1000.0 / t;
        let x = -3.0258469 * inv_t.powi(3) + 2.1070379 * inv_t.powi(2) + 0.2226347 * inv_t + 0.240390;
        let y = -3.000 * x.powi(2) + 2.870 * x - 0.275;
        (x, y)
    };

    // CIE XYZ for destination white point
    let y_safe = y.max(0.0001);
    let xd = x / y_safe;
    let yd = 1.0f32;
    let zd = (1.0 - x - y) / y_safe;

    // Reference white point D65
    let xs = 0.95047f32;
    let ys = 1.00000f32;
    let zs = 1.08883f32;

    // Bradford cone response transformation
    // [ rho, gamma, beta ]^T = M_BFD * [ X, Y, Z ]^T
    let rho_s =  0.8951 * xs + 0.2664 * ys - 0.1614 * zs;
    let gam_s = -0.7502 * xs + 1.7135 * ys + 0.0367 * zs;
    let bet_s =  0.0389 * xs - 0.0685 * ys + 1.0296 * zs;

    let rho_d =  0.8951 * xd + 0.2664 * yd - 0.1614 * zd;
    let gam_d = -0.7502 * xd + 1.7135 * yd + 0.0367 * zd;
    let bet_d =  0.0389 * xd - 0.0685 * yd + 1.0296 * zd;

    let k_r = (rho_d / rho_s.max(0.0001)) * gamma_comp;
    let k_g = (gam_d / gam_s.max(0.0001)) * gamma_comp;
    let k_b = (bet_d / bet_s.max(0.0001)) * gamma_comp;

    (k_r.clamp(0.5, 1.5), k_g.clamp(0.5, 1.5), k_b.clamp(0.5, 1.5))
}

/// Injects Bradford CAT calibrated Gamma LUT directly into the Windows GPU hardware ramp.
#[cfg(target_os = "windows")]
pub fn apply_hardware_gamma_ramp(cct_kelvin: u32, gamma_comp: f32) -> Result<()> {
    use std::ffi::c_void;

    #[repr(C)]
    struct DDKGAMMARAMP {
        red: [u16; 256],
        green: [u16; 256],
        blue: [u16; 256],
    }

    extern "system" {
        fn GetDC(hWnd: *mut c_void) -> *mut c_void;
        fn ReleaseDC(hWnd: *mut c_void, hDC: *mut c_void) -> i32;
        fn SetDeviceGammaRamp(hDC: *mut c_void, lpRamp: *const c_void) -> i32;
    }

    let (kr, kg, kb) = calculate_bradford_multipliers(cct_kelvin, gamma_comp);

    let mut ramp = DDKGAMMARAMP {
        red: [0; 256],
        green: [0; 256],
        blue: [0; 256],
    };

    for i in 0..256 {
        let base = (i as f32 / 255.0).powf(1.0 / 1.05) * 65535.0;
        ramp.red[i] = ((base * kr).clamp(0.0, 65535.0)) as u16;
        ramp.green[i] = ((base * kg).clamp(0.0, 65535.0)) as u16;
        ramp.blue[i] = ((base * kb).clamp(0.0, 65535.0)) as u16;
    }

    unsafe {
        let hdc = GetDC(std::ptr::null_mut());
        if hdc.is_null() {
            anyhow::bail!("Failed to acquire screen device context via GetDC(NULL)");
        }
        let res = SetDeviceGammaRamp(hdc, &ramp as *const _ as *const c_void);
        ReleaseDC(std::ptr::null_mut(), hdc);
        if res == 0 {
            anyhow::bail!("SetDeviceGammaRamp failed on Windows host display");
        }
    }

    tracing::info!("🎨 Windows GPU Gamma LUT updated via Bradford CAT: CCT={}K, Comp={:.2}x", cct_kelvin, gamma_comp);
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn apply_hardware_gamma_ramp(cct_kelvin: u32, gamma_comp: f32) -> Result<()> {
    tracing::info!("🎨 Simulated Gamma LUT Ramp on macOS/Unix: CCT={}K, Comp={:.2}x", cct_kelvin, gamma_comp);
    Ok(())
}

/// Restores the identity/linear gamma ramp on the display.
#[allow(dead_code)]
#[cfg(target_os = "windows")]
pub fn reset_hardware_gamma_ramp() -> Result<()> {
    use std::ffi::c_void;

    #[repr(C)]
    struct DDKGAMMARAMP {
        red: [u16; 256],
        green: [u16; 256],
        blue: [u16; 256],
    }

    extern "system" {
        fn GetDC(hWnd: *mut c_void) -> *mut c_void;
        fn ReleaseDC(hWnd: *mut c_void, hDC: *mut c_void) -> i32;
        fn SetDeviceGammaRamp(hDC: *mut c_void, lpRamp: *const c_void) -> i32;
    }

    let mut ramp = DDKGAMMARAMP {
        red: [0; 256],
        green: [0; 256],
        blue: [0; 256],
    };

    for i in 0..256 {
        let val = ((i as f32 / 255.0) * 65535.0) as u16;
        ramp.red[i] = val;
        ramp.green[i] = val;
        ramp.blue[i] = val;
    }

    unsafe {
        let hdc = GetDC(std::ptr::null_mut());
        if !hdc.is_null() {
            SetDeviceGammaRamp(hdc, &ramp as *const _ as *const c_void);
            ReleaseDC(std::ptr::null_mut(), hdc);
        }
    }
    tracing::info!("🎨 Restored neutral identity gamma ramp on Windows host");
    Ok(())
}

#[allow(dead_code)]
#[cfg(not(target_os = "windows"))]
pub fn reset_hardware_gamma_ramp() -> Result<()> {
    Ok(())
}
