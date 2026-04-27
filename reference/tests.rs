use haybale::Error;
use haybale::Project;
use std::path::Path;
use std::sync::Once;
use test_haybale::checkers::CheckResult;
use test_haybale::exec::symex_and_check;
// TODO: currently these tests just make sure that negative tests get an error, and positive tests get an ok
// we should probably check that they're actually getting the right errors

static INIT: Once = Once::new();

/// Setup function that is only run once, even if called multiple times.
fn setup_logger() {
    INIT.call_once(|| {
        env_logger::init();
    });
}

/// Helper to run symex_and_check and assert the result is as expected
fn run_and_assert_err(func_name: &str, expect_err: bool) {
    setup_logger();
    let binary_path = Path::new("../examples/host.bc");
    let project = Project::from_bc_path(binary_path).unwrap();
    let loop_bound = 1000;
    let results = symex_and_check(
        func_name,
        &project,
        loop_bound,
        binary_path.to_str().unwrap(),
    );
    assert!(results.len() > 0); // real code should always have at least 1 path through it
    for result in results {
        if expect_err {
            assert!(result.is_err(), "Expected Err, got: {:?}", result);
        } else {
            assert!(result.is_ok(), "Expected Ok, got: {:?}", result);
        }
    }
}

/// Helper to run symex_and_check and assert the result matches the expected slice
fn run_and_assert_results(func_name: &str, expected_results: &[CheckResult]) {
    setup_logger();
    let binary_path = Path::new("../examples/host.bc");
    let project = Project::from_bc_path(binary_path).unwrap();
    let loop_bound = 1000;
    let results = symex_and_check(
        func_name,
        &project,
        loop_bound,
        binary_path.to_str().unwrap(),
    );
    assert_eq!(
        results, expected_results,
        "Results did not match expected slice.\nExpected: {:?}\nGot: {:?}",
        expected_results, results
    );
}

#[test]
fn test_sandbox_array_index_unchecked_unsafe() {
    run_and_assert_results(
        "sandbox_array_index_unchecked_unsafe",
        &[Err(Error::OtherError("CheckErr::Oob".to_string()))],
    );
}

#[test]
fn test_sandbox_array_index_unchecked_safe() {
    run_and_assert_results(
        "sandbox_array_index_unchecked_safe",
        &[Err(Error::OtherError("CheckErr::Oob".to_string()))],
    );
}

#[test]
fn test_sandbox_primitive_array_index_unchecked_unsafe() {
    run_and_assert_results(
        "sandbox_primitive_array_index_unchecked_unsafe",
        &[Err(Error::OtherError("CheckErr::Oob".to_string()))],
    );
}

#[test]
fn test_sandbox_array_index_checked() {
    run_and_assert_results("sandbox_array_index_checked", &[Ok(()), Ok(()), Ok(())]);
}

#[test]
fn test_basic_oob_read() {
    run_and_assert_results(
        "basic_oob_read",
        &[Err(Error::OtherError("CheckErr::Oob".to_string()))],
    );
}

#[test]
fn test_basic_oob_write() {
    run_and_assert_results(
        "basic_oob_write",
        &[Err(Error::OtherError("CheckErr::Oob".to_string()))],
    );
}

#[test]
fn test_basic_oob_read_from_arg() {
    run_and_assert_results(
        "basic_oob_read_from_arg",
        &[Err(Error::OtherError("CheckErr::Oob".to_string()))],
    );
}

#[test]
fn test_trivial_array_read() {
    run_and_assert_results("trivial_array_read", &[Ok(())]);
}

#[test]
fn test_repeaated_array_read() {
    run_and_assert_results("repeated_array_read", &[Ok(())]);
}

#[test]
fn test_trivial_array_read_2d() {
    run_and_assert_results("trivial_array_read_2d", &[Ok(())]);
}

#[test]
fn test_trivial_struct_read() {
    run_and_assert_results("trivial_struct_read", &[Ok(())]);
}

#[test]
fn test_trivial_struct_read_nested() {
    run_and_assert_results("trivial_struct_read_nested", &[Ok(())]);
}

#[test]
fn test_basic_null_read() {
    run_and_assert_results(
        "basic_null_read",
        &[Err(Error::OtherError(
            "CheckErr::DereferencedNull".to_string(),
        ))],
    );
}

#[test]
fn test_basic_null_write() {
    run_and_assert_results(
        "basic_null_write",
        &[Err(Error::OtherError(
            "CheckErr::DereferencedNull".to_string(),
        ))],
    );
}

#[test]
fn test_basic_null_write2() {
    run_and_assert_results(
        "basic_null_write2",
        &[Err(Error::OtherError(
            "CheckErr::DereferencedNull".to_string(),
        ))],
    );
}

#[test]
fn test_basic_div_by_zero() {
    run_and_assert_results(
        "basic_div_by_zero",
        &[Err(Error::OtherError("CheckErr::Poison".to_string()))],
    );
}

#[test]
fn test_basic_div_by_zero2() {
    run_and_assert_results(
        "basic_div_by_zero2",
        &[Err(Error::OtherError(
            "CheckErr::DividedByZero".to_string(),
        ))],
    );
}

#[test]
fn test_basic_div_by_zero_guarded() {
    run_and_assert_results("basic_div_by_zero_guarded", &[Ok(()), Ok(())]);
}

#[test]
fn test_libjpeg_example() {
    setup_logger();
    let binary_path = Path::new(
        "../example-rlbox-libjpeg-bench/build_nosimd_debug/image_change_quality_rlbox_noop.bc",
    );
    let project = Project::from_bc_path(binary_path).unwrap();
    let loop_bound = 5;
    let results = symex_and_check("main", &project, loop_bound, binary_path.to_str().unwrap());
    // let results = symex_and_check("write_jpeg", &project, loop_bound);
    let expected_results = &[Ok(())];
    assert_eq!(
        results, expected_results,
        "Results did not match expected slice.\nExpected: {:?}\nGot: {:?}",
        expected_results, results
    );
}
