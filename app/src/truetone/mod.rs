//! # Cross-Screen TrueTone & Bradford Chromatic Adaptation Engine
//!
//! ## 1. Module Purpose & Scope
//! This module provides real-time ambient color temperature synchronization and chromatic adaptation
//! between a macOS host equipped with an Apple Ambient Light Sensor (ALS) and a paired Windows 10/11
//! workstation.
//!
//! When a MacBook Pro is positioned alongside an external Windows monitor, differences in panel
//! native white points and room lighting can cause significant visual fatigue and jarring color
//! mismatch. This module:
//! 1. Telemeters ambient illumination (lux) and Correlated Color Temperature (CCT in Kelvin) from
//!    the Mac hardware sensor (`ambient_light.swift`).
//! 2. Solves the CIE daylight / Planckian locus chromaticity equations to derive destination XYZ
//!    tristimulus white points.
//! 3. Applies the Bradford Chromatic Adaptation Transform (CAT) in cone response space to calculate
//!    per-channel linear sRGB multipliers `(k_r, k_g, k_b)`.
//! 4. Injects calibrated 256-entry hardware gamma lookup tables (LUT) directly into the Windows GPU
//!    using the Win32 GDI `SetDeviceGammaRamp` API.
//!
//! ## 2. Architectural Linkages & Dependencies
//!
//! ```text
//! ┌────────────────────────────────────────────────────────────────────────────────────────┐
//! │                          TrueTone & Chromatic Adaptation Flow                          │
//! └────────────────────────────────────────────────────────────────────────────────────────┘
//!
//!                 MacBook (Host)                               Windows 11 (Client)
//!     ┌──────────────────────────────────┐             ┌──────────────────────────────────┐
//!     │ Apple Ambient Light Sensor (ALS) │             │ Windows Display Controller       │
//!     │ IOKit HID (ambient_light.swift)  │             │ (src/display/win_display.rs)     │
//!     └────────────────┬─────────────────┘             └────────────────▲─────────────────┘
//!                      │                                                │
//!                      │ lux, CCT (2500K..9000K)                        │ apply_hardware_
//!                      ▼                                                │ gamma_ramp()
//!     ┌──────────────────────────────────┐                              │
//!     │   read_ambient_light()           │                              │
//!     │   (src/truetone/mod.rs)          │                              │
//!     └────────────────┬─────────────────┘                              │
//!                      │ Telemetry Broadcast (UDP / RPC)                │
//!                      ├────────────────────────────────────────────────┘
//!                      │
//!                      ▼
//!     ┌──────────────────────────────────┐
//!     │ Bradford CAT Matrix Transform    │
//!     │ - CIE D-Illuminant / Planckian   │
//!     │ - Cone Response Scaling (M_BFD)  │
//!     │ - SetDeviceGammaRamp GDI API     │
//!     └──────────────────────────────────┘
//! ```
//!
//! ### Upstream Callers:
//! - `src/core.rs`: Periodically samples ambient light and synchronizes display white points.
//! - Settings UI: Allows users to toggle Cross-Screen TrueTone and calibrate intensity.
//!
//! ### Downstream Callees:
//! - `src/ambient_light.swift`: FFI bridge to Apple IOKit HID ambient light sensor.
//! - Win32 GDI32: `SetDeviceGammaRamp`, `GetDC`, and `ReleaseDC` on Windows.
//!
//! ## 3. Mathematical Foundations: Bradford CAT
//! - **Reference White Point**: Standard CIE D65 (`x = 0.3127, y = 0.3290`, `X = 0.95047, Y = 1.00000, Z = 1.08883`).
//! - **Target White Point**: Computed using CIE Daylight equations (for CCT >= 4000K) or the Kang 2002
//!   Planckian approximation (for CCT < 4000K).
//! - **Cone Transformation**: XYZ values are projected into Bradford cone response space via matrix $M_{BFD}$:
//!   $$\begin{bmatrix} \rho \\ \gamma \\ \beta \end{bmatrix} = \begin{bmatrix} 0.8951 & 0.2664 & -0.1614 \\ -0.7502 & 1.7135 & 0.0367 \\ 0.0389 & -0.0685 & 1.0296 \end{bmatrix} \begin{bmatrix} X \\ Y \\ Z \end{bmatrix}$$
//! - Scaling ratios $s_\rho = \rho_d / \rho_s$, $s_\gamma = \gamma_d / \gamma_s$, $s_\beta = \beta_d / \beta_s$
//!   are applied and mapped back through $M_{BFD}^{-1}$ into linear sRGB space.
//!
//! ## 4. Security & Safety Invariants
//! - **Finite Number Guarantee**: All multipliers and gamma values are verified for finite validity
//!   (`is_finite()`). Any `NaN` or `Inf` value safely falls back to neutral 1.0.
//! - **LUT Ramp Clamping**: Color temperature is clamped to `[2500, 9000] K` and multipliers are
//!   clamped to `[0.4, 1.5]`, preventing display blackout or severe tinting.

use crate::config::{
    D65_CCT_KELVIN, MAX_CCT_KELVIN, MAX_GAMMA_COMP_FACTOR, MIN_CCT_KELVIN, MIN_GAMMA_COMP_FACTOR,
};
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
        if ok && lux.is_finite() && lux >= 0.0 {
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
                lux: 0.0,
                cct_kelvin: D65_CCT_KELVIN,
                supported: false,
                updated_at_secs: 0,
            }
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        AmbientLightData {
            lux: 0.0,
            cct_kelvin: D65_CCT_KELVIN,
            supported: false,
            updated_at_secs: 0,
        }
    }
}

/// Calculates Bradford Chromatic Adaptation Transform linear sRGB scaling factors
/// for target ambient CCT (Kelvin) relative to standard D65 (6500K) white point.
#[allow(dead_code)]
pub fn calculate_bradford_multipliers(cct_kelvin: u32, gamma_comp: f32) -> (f32, f32, f32) {
    let safe_gamma = if gamma_comp.is_finite() {
        gamma_comp.clamp(MIN_GAMMA_COMP_FACTOR, MAX_GAMMA_COMP_FACTOR)
    } else {
        1.0
    };
    let t = cct_kelvin.clamp(MIN_CCT_KELVIN, MAX_CCT_KELVIN) as f32;

    // CIE Daylight (D-illuminant) for >= 4000K so 6500K aligns with D65; Kang 2002 Planckian below 4000K.
    let inv_t = 1000.0 / t;
    let (x, y) = if t < 4000.0 {
        let x = -0.2661239 * inv_t.powi(3) - 0.2343580 * inv_t.powi(2)
            + 0.8776956 * inv_t
            + 0.179910;
        let y = if t <= 2222.0 {
            -1.1063814 * x.powi(3) - 1.34811020 * x.powi(2) + 2.18555832 * x - 0.20219683
        } else {
            -0.9549476 * x.powi(3) - 1.37418593 * x.powi(2) + 2.09137015 * x - 0.16748867
        };
        (x, y)
    } else {
        let x = if t <= 7000.0 {
            -4.6070 * inv_t.powi(3) + 2.9678 * inv_t.powi(2) + 0.09911 * inv_t + 0.244063
        } else {
            -2.0064 * inv_t.powi(3) + 1.9018 * inv_t.powi(2) + 0.24748 * inv_t + 0.237040
        };
        let y = -3.0 * x.powi(2) + 2.87 * x - 0.275;
        (x, y)
    };

    // CIE XYZ for destination white point (Y = 1.0)
    let y_safe = y.max(0.0001);
    let xd = x / y_safe;
    let yd = 1.0f32;
    let zd = ((1.0 - x - y) / y_safe).max(0.0);

    // Reference white point D65
    let xs = 0.95047f32;
    let ys = 1.00000f32;
    let zs = 1.08883f32;

    // Bradford cone response scaling adapted to XYZ -> linear sRGB
    let rho_s = 0.8951 * xs + 0.2664 * ys - 0.1614 * zs;
    let gam_s = -0.7502 * xs + 1.7135 * ys + 0.0367 * zs;
    let bet_s = 0.0389 * xs - 0.0685 * ys + 1.0296 * zs;

    let rho_d = 0.8951 * xd + 0.2664 * yd - 0.1614 * zd;
    let gam_d = -0.7502 * xd + 1.7135 * yd + 0.0367 * zd;
    let bet_d = 0.0389 * xd - 0.0685 * yd + 1.0296 * zd;

    let s_r = (rho_d / rho_s.max(0.0001)).clamp(0.4, 2.0);
    let s_g = (gam_d / gam_s.max(0.0001)).clamp(0.4, 2.0);
    let s_b = (bet_d / bet_s.max(0.0001)).clamp(0.4, 2.0);

    // Adapted D65 white in Bradford cone space, mapped back via M_BFD^-1 to XYZ then linear sRGB
    let a_rho = s_r * rho_s;
    let a_gam = s_g * gam_s;
    let a_bet = s_b * bet_s;

    // Exact inverse Bradford M_BFD^-1
    let ax = 0.9869929 * a_rho - 0.1470543 * a_gam + 0.1599627 * a_bet;
    let ay = 0.4323053 * a_rho + 0.5183603 * a_gam + 0.0492912 * a_bet;
    let az = -0.0085287 * a_rho + 0.0400428 * a_gam + 0.9684867 * a_bet;

    // CIE XYZ -> linear sRGB (D65)
    let r_lin = 3.2404542 * ax - 1.5371385 * ay - 0.4985314 * az;
    let g_lin = -0.9692660 * ax + 1.8760108 * ay + 0.0415560 * az;
    let b_lin = 0.0556434 * ax - 0.2040259 * ay + 1.0572252 * az;

    let max_chan = r_lin.max(g_lin).max(b_lin).max(0.0001);
    let k_r = ((r_lin / max_chan) * safe_gamma).clamp(0.4, 1.5);
    let k_g = ((g_lin / max_chan) * safe_gamma).clamp(0.4, 1.5);
    let k_b = ((b_lin / max_chan) * safe_gamma).clamp(0.4, 1.5);

    (
        if k_r.is_finite() { k_r } else { 1.0 },
        if k_g.is_finite() { k_g } else { 1.0 },
        if k_b.is_finite() { k_b } else { 1.0 },
    )
}

#[cfg(target_os = "windows")]
#[repr(C)]
struct DdkGammaRamp {
    red: [u16; 256],
    green: [u16; 256],
    blue: [u16; 256],
}

#[cfg(target_os = "windows")]
fn apply_windows_gamma_ramp(ramp: &DdkGammaRamp) -> Result<()> {
    use std::ffi::c_void;

    #[link(name = "gdi32")]
    extern "system" {
        fn SetDeviceGammaRamp(h_dc: *mut c_void, lp_ramp: *const c_void) -> i32;
    }
    #[link(name = "user32")]
    extern "system" {
        fn GetDC(h_wnd: *mut c_void) -> *mut c_void;
        fn ReleaseDC(h_wnd: *mut c_void, h_dc: *mut c_void) -> i32;
    }

    unsafe {
        let hdc = GetDC(std::ptr::null_mut());
        if hdc.is_null() {
            anyhow::bail!("Failed to acquire screen device context via GetDC(NULL)");
        }
        let res = SetDeviceGammaRamp(hdc, ramp as *const _ as *const c_void);
        ReleaseDC(std::ptr::null_mut(), hdc);
        if res == 0 {
            anyhow::bail!("SetDeviceGammaRamp failed on Windows host display");
        }
    }
    Ok(())
}

/// Injects Bradford CAT calibrated Gamma LUT directly into the Windows GPU hardware ramp.
#[cfg(target_os = "windows")]
pub fn apply_hardware_gamma_ramp(cct_kelvin: u32, gamma_comp: f32) -> Result<()> {
    let (kr, kg, kb) = calculate_bradford_multipliers(cct_kelvin, gamma_comp);

    let mut ramp = DdkGammaRamp {
        red: [0; 256],
        green: [0; 256],
        blue: [0; 256],
    };

    for i in 0..256 {
        let base = (i as f32 / 255.0).powf(1.0 / 1.05) * 65535.0;
        ramp.red[i] = (base * kr).clamp(0.0, 65535.0).round() as u16;
        ramp.green[i] = (base * kg).clamp(0.0, 65535.0).round() as u16;
        ramp.blue[i] = (base * kb).clamp(0.0, 65535.0).round() as u16;
    }

    apply_windows_gamma_ramp(&ramp)?;

    tracing::info!(
        "🎨 Windows GPU Gamma LUT updated via Bradford CAT: CCT={}K, Comp={:.2}x",
        cct_kelvin,
        if gamma_comp.is_finite() { gamma_comp } else { 1.0 }
    );
    Ok(())
}

#[cfg(not(target_os = "windows"))]
pub fn apply_hardware_gamma_ramp(cct_kelvin: u32, gamma_comp: f32) -> Result<()> {
    let safe_gamma = if gamma_comp.is_finite() { gamma_comp } else { 1.0 };
    tracing::info!(
        "🎨 Simulated Gamma LUT Ramp on macOS/Unix: CCT={}K, Comp={:.2}x",
        cct_kelvin,
        safe_gamma
    );
    Ok(())
}

/// Restores the identity/linear gamma ramp on the display.
#[allow(dead_code)]
#[cfg(target_os = "windows")]
pub fn reset_hardware_gamma_ramp() -> Result<()> {
    let mut ramp = DdkGammaRamp {
        red: [0; 256],
        green: [0; 256],
        blue: [0; 256],
    };

    for i in 0..256 {
        let val = ((i as f32 / 255.0) * 65535.0).round() as u16;
        ramp.red[i] = val;
        ramp.green[i] = val;
        ramp.blue[i] = val;
    }

    apply_windows_gamma_ramp(&ramp)?;
    tracing::info!("🎨 Restored neutral identity gamma ramp on Windows host");
    Ok(())
}

#[allow(dead_code)]
#[cfg(not(target_os = "windows"))]
pub fn reset_hardware_gamma_ramp() -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bradford_handles_nan_inf_and_preserves_finite_bounds() {
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY, -5.0, 0.0] {
            let (r, g, b) = calculate_bradford_multipliers(D65_CCT_KELVIN, bad);
            assert!(r.is_finite() && (0.4..=1.5).contains(&r));
            assert!(g.is_finite() && (0.4..=1.5).contains(&g));
            assert!(b.is_finite() && (0.4..=1.5).contains(&b));
        }
        let (r65, g65, b65) = calculate_bradford_multipliers(D65_CCT_KELVIN, 1.0);
        assert!((r65 - 1.0).abs() < 0.05 && (g65 - 1.0).abs() < 0.05 && (b65 - 1.0).abs() < 0.05);
    }
}
