use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ventris"))
        .args(args)
        .output()
        .expect("run ventris binary")
}

fn run_owned(args: &[String]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ventris"))
        .args(args)
        .output()
        .expect("run ventris binary")
}

fn fixture() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../integrations/vscode/acceptance/fixture.exe")
}

#[test]
fn help_is_a_successful_machine_invocation() {
    let output = run(&["help"]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ventris inspect <image>"), "{stdout}");
    assert!(stdout.contains("arm32"), "{stdout}");
    assert!(stdout.contains("rv64"), "{stdout}");
    assert!(stdout.contains("ppc32"), "{stdout}");
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn unknown_command_is_an_actionable_usage_error() {
    let output = run(&["no-such-command"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown command"), "{stderr}");
    assert!(stderr.contains("Usage:"), "{stderr}");
}

#[test]
fn native_decompile_requires_architecture() {
    let output = run(&["decompile", "missing", "0x1000"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--arch"), "{stderr}");
}

#[test]
fn inspect_json_is_a_stable_success_envelope() {
    let image = fixture().to_string_lossy().replace('\\', "/");
    let args = vec!["inspect".into(), image, "--json".into()];
    let output = run_owned(&args);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("{\"command\":\"inspect\""), "{stdout}");
    assert!(stdout.contains("\"ok\":true"), "{stdout}");
    assert!(stdout.contains("\"result\":"), "{stdout}");
}

#[test]
fn raw_mips_ps2_decompile_smoke() {
    let path = std::env::temp_dir().join(format!("ventris-mips-ps2-{}.bin", std::process::id()));
    let bytes: Vec<u8> =
        include_str!("../../ventris-decompiler/testdata/public/mips_ps2_fade_start.hex")
            .split_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).expect("valid MIPS fixture byte"))
            .collect();
    std::fs::write(&path, bytes).expect("write raw MIPS fixture");

    let args = vec![
        "decompile".to_string(),
        path.to_string_lossy().into_owned(),
        "0x1000".to_string(),
        "--arch".to_string(),
        "mips32".to_string(),
        "--raw".to_string(),
        "--limit".to_string(),
        "16".to_string(),
        "--json".to_string(),
    ];
    let output = run_owned(&args);
    let _ = std::fs::remove_file(&path);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("{\"command\":\"decompile\""), "{stdout}");
    assert!(stdout.contains("\"ok\":true"), "{stdout}");
    assert!(stdout.contains("uint16_t"), "{stdout}");
    assert!(stdout.contains("bool"), "{stdout}");
}

#[test]
fn raw_mips_ps2_source_reconstruction_smoke() {
    let path = std::env::temp_dir().join(format!("ventris-mips-source-{}.bin", std::process::id()));
    let bytes: Vec<u8> =
        include_str!("../../ventris-decompiler/testdata/public/mips_ps2_fade_start.hex")
            .split_whitespace()
            .map(|byte| u8::from_str_radix(byte, 16).expect("valid MIPS fixture byte"))
            .collect();
    std::fs::write(&path, bytes).expect("write raw MIPS fixture");

    let args = vec![
        "decompile".to_string(),
        path.to_string_lossy().into_owned(),
        "0x1000".to_string(),
        "--target".to_string(),
        "ps2".to_string(),
        "--raw".to_string(),
        "--limit".to_string(),
        "16".to_string(),
        "--json".to_string(),
    ];
    let output = run_owned(&args);
    let _ = std::fs::remove_file(&path);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("{\"command\":\"decompile\""), "{stdout}");
    assert!(stdout.contains("\"ok\":true"), "{stdout}");
    assert!(stdout.contains("#include <stdint.h>"), "{stdout}");
    assert!(stdout.contains("uint16_t"), "{stdout}");
}

#[test]
fn json_errors_use_stdout_without_usage_noise() {
    let output = run(&["inspect", "missing", "--json"]);
    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"ok\":false"), "{stdout}");
    assert!(stdout.contains("\"error\":"), "{stdout}");
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
