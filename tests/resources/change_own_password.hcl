# Path includes a placeholder that will be replaced by Rust code, not Vault
path "auth/foo/users/{{identity.entity.aliases.${userpass_accessor}.name}}/password" {
    capabilities = ["update"]
}