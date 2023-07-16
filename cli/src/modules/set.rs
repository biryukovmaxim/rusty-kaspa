use crate::imports::*;

#[derive(Default, Handler)]
#[help("Halt execution (used for testing)")]
pub struct Set;

impl Set {
    async fn main(self: Arc<Self>, ctx: &Arc<dyn Context>, argv: Vec<String>, _cmd: &str) -> Result<()> {
        let ctx = ctx.clone().downcast_arc::<KaspaCli>()?;

        if argv.is_empty() {
            tprintln!(ctx, "\nSettings:\n");
            let list = Settings::list();
            let list = list
                .iter()
                .map(|setting| {
                    let value: String = ctx.wallet().settings().get(setting.clone()).unwrap_or_else(|| "-".to_string());
                    let descr = setting.descr();
                    (setting.to_lowercase_string(), value, descr)
                })
                .collect::<Vec<(_, _, _)>>();
            let c1 = list.iter().map(|(c, _, _)| c.len()).fold(0, |a, b| a.max(b)) + 4;
            let c2 = list.iter().map(|(_, c, _)| c.len()).fold(0, |a, b| a.max(b)) + 4;

            list.iter().for_each(|(k, v, d)| {
                tprintln!(ctx, "{}: {} \t {}", k.pad_to_width_with_alignment(c1, pad::Alignment::Right), v.pad_to_width(c2), d);
            });
        } else if argv.len() != 2 {
            tprintln!(ctx, "\n\rError:\n\r");
            tprintln!(ctx, "Usage:\n\rset <key> <value>");
            return Ok(());
        } else {
            let key = argv[0].as_str();
            let value = argv[1].as_str().trim();

            if value.contains(' ') || value.contains('\t') {
                return Err(Error::Custom("Whitespace in settings is not allowed".to_string()));
            }

            match key {
                "network" => {
                    let network: NetworkType = value.parse().map_err(|_| "Unknown network type".to_string())?;
                    ctx.wallet().settings().set(Settings::Network, network).await?;
                }
                "server" => {
                    ctx.wallet().settings().set(Settings::Server, value).await?;
                }
                "wallet" => {
                    ctx.wallet().settings().set(Settings::Wallet, value).await?;
                }
                _ => return Err(Error::Custom(format!("Unknown setting '{}'", key))),
            }
            ctx.wallet().settings().try_store().await?;
        }

        Ok(())
    }
}