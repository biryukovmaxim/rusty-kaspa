use crate::imports::*;

#[derive(Default, Handler)]
#[help("Basic command guide for using this software.")]
pub struct Guide;

impl Guide {
    async fn main(self: Arc<Self>, ctx: &Arc<dyn Context>, _argv: Vec<String>, _cmd: &str) -> cli::Result<()> {
        let term = ctx.term();
        let guide = include_str!("guide.txt");

        let mut info: Vec<(String, String)> = vec![];
        let lines = guide.split('\n');
        let mut cmd = String::new();
        let mut help = String::new();
        let remove_prefixes_regex = Regex::new(r"^#(\[desktop\])?\s*").unwrap();
        let collapse_spaces_regex = Regex::new(r"\s+").unwrap();
        for line in lines {
            if line.starts_with('#') {
                if !cmd.is_empty() {
                    info.push((cmd.clone(), collapse_spaces_regex.replace_all(&help, " ").trim().to_string()));
                    cmd.clear();
                    help.clear();
                } else {
                    help.clear();
                }
                cmd.push_str(&line.to_lowercase());
            } else {
                help.push_str(line);
                help.push(' ');
            }
        }

        if !cmd.is_empty() {
            info.push((cmd.clone(), help.trim().to_string()));
            cmd.clear();
            help.clear();
        }

        let term_width: usize = term.cols().unwrap_or(80);
        let col1 = info.iter().map(|(cmd, _)| cmd.len()).max().unwrap() + 4;
        let col2 = term_width - col1 - 2;

        term.writeln("");

        for (cmd, help) in info.iter() {
            if cmd.trim() == "#" {
                let options = textwrap::Options::new(term_width).line_ending(textwrap::LineEnding::CRLF);
                textwrap::wrap(help.as_str(), options).into_iter().for_each(|line| {
                    term.writeln(style(line).black().to_string());
                });
            } else {
                if !application_runtime::is_nw() && cmd.starts_with("#[desktop]") {
                    continue;
                }
                let cmd = remove_prefixes_regex.replace(cmd, "");
                let cmd = format!("'{cmd}'").pad_to_width(col1);
                let space = "".pad_to_width(col1);
                let mut first = true;
                let options = textwrap::Options::new(col2).line_ending(textwrap::LineEnding::CRLF);
                textwrap::wrap(help.as_str(), options).into_iter().for_each(|line| {
                    if first {
                        term.writeln(format!("{}{}", style(&cmd).black().italic(), style(line).black()));
                        first = false;
                    } else {
                        term.writeln(format!("{space}{}", style(line).black()));
                    }
                });
            }
            term.writeln("");
        }

        Ok(())
    }
}
