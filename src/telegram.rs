use serde_json::json;

use crate::db::User;

#[derive(Clone)]
pub struct TelegramNotifier {
    client: reqwest::Client,
    token: String,
    chat_id: String,
}

impl TelegramNotifier {
    pub fn new(token: String, chat_id: String) -> Self {
        Self {
            client: reqwest::Client::new(),
            token,
            chat_id,
        }
    }

    pub async fn notify_new_user(&self, user: &User) -> Result<(), String> {
        let text = format!(
            "New user registered\nID: {}\nUsername: {}\nEmail: {}\nRole: {}\nCreated at: {}",
            user.id, user.username, user.email, user.role, user.created_at
        );
        let url = format!("https://api.telegram.org/bot{}/sendMessage", self.token);
        let response = self
            .client
            .post(url)
            .json(&json!({
                "chat_id": self.chat_id,
                "text": text,
            }))
            .send()
            .await
            .map_err(|err| err.to_string())?;
        if !response.status().is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(format!("Telegram API returned {body}"));
        }
        Ok(())
    }
}
