use std::borrow::Borrow;
use std::fs::File;
use std::path::Path;
use tempfile::NamedTempFile;

pub const VAULT_CONFIG_PATH: &str = "/vault/config/config.hcl";

pub const VAULT_CONFIG_HCL: &str = "storage \"file\" {
    path    = \"/vault/file\"
}

listener \"tcp\" {
   address = \"0.0.0.0:8200\"
   tls_disable = true
}

ui = false";

pub fn create_vault_config_file_with_content<C>(content: C) -> Result<NamedTempFile, std::io::Error>
where
    C: Borrow<str>
{
    use std::io::Write;

    let mut ntf = NamedTempFile::new()?;
    write!(ntf, "{}", content.borrow())?;

    set_vault_config_permissions(ntf.path())?;

    Ok(ntf)
}

pub fn set_vault_config_permissions(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;

    let f = File::open(path)?;
    f.set_permissions(PermissionsExt::from_mode(0o644))
}

