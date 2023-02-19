use std::str::FromStr;

#[derive(PartialEq)]
pub enum WorkingMode {
    KeyPairGeneration,
    Sign,
    Verify
}

impl FromStr for WorkingMode {
    type Err = ();

    fn from_str(input: &str) -> Result<WorkingMode, Self::Err> {
        match input {
            "generatekeypair"  => Ok(WorkingMode::KeyPairGeneration),
            "sign"  => Ok(WorkingMode::Sign),
            "verify"  => Ok(WorkingMode::Verify),
            _      => Err(()),
        }
    }
}