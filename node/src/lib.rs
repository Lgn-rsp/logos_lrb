//! Библиотечная часть узла LOGOS: экспортируем AppState, auth и archive.
//! Нужна для случаев, когда crate собирается как `lib`.

pub mod state;
pub use state::AppState;

pub mod auth;
pub use auth::require_bridge;

// ВАЖНО: подключаем архив, чтобы `crate::archive::...` существовал и в lib-сборке.
pub mod archive;
