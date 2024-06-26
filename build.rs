use std::{env, fs};

use handlebars::Handlebars;
use serde_json::json;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BuildError {
    #[error("environment variable not set: {0}")]
    EnvironmentVariableNotSet(String),
}

fn read_env(key: &str) -> Result<String, BuildError> {
    return env::var(key)
        .map_err(|_| BuildError::EnvironmentVariableNotSet(key.to_string()));
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::compile_protos("proto/wgrpcd.proto")?;

    match env::var("CLOUD_INIT") {
        Ok(_) => {
            let ca_cn = read_env("CA_CN")?;
            let ca_country = read_env("CA_COUNTRY")?;
            let ca_state = read_env("CA_STATE")?;
            let ca_city = read_env("CA_CITY")?;
            let ca_company = read_env("CA_COMPANY")?;
            let wgrpcd_cn = read_env("WGRPCD_CN")?;

            let admin_ssh_key_filename = read_env("ADMIN_SSH_KEY")?;
            let deploy_ssh_key_filename = read_env("DEPLOY_SSH_KEY")?;
            let admin_ssh_key = fs::read_to_string(admin_ssh_key_filename)?;
            let deploy_ssh_key = fs::read_to_string(deploy_ssh_key_filename)?;

            let context = json!({
                "admin_ssh_key": admin_ssh_key,
                "deploy_ssh_key": deploy_ssh_key,
                "ca_cn": ca_cn,
                "ca_country": ca_country,
                "ca_state": ca_state,
                "ca_city": ca_city,
                "ca_company": ca_company,
                "server_cn": wgrpcd_cn,
                "server_state": ca_state,
                "server_city": ca_city,
                "server_company": ca_company,
            });

            let mut handlebars = Handlebars::new();
            handlebars.register_template_file("cloud-init", "init-scripts/cloud-init-wgrpcd.yaml")?;

            let cloud_init = handlebars.render("cloud-init", &context)?;
            fs::write("wgrpcd-cloud-init-deploy.yml", cloud_init)?;
            Ok(())
        }
        Err(_) => {
            Ok(())
        }
    }
}