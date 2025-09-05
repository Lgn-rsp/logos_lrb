/*!
 * LOGOS LRB — core crate
 * Экспорт модулей ядра L1: типы, консенсус, мемпул/баланс, резонанс, сигналы, защита.
 * Здесь только декларация модулей — реализация в соответствующих *.rs файлах.
 */

pub mod types;

pub mod anti_replay;
pub mod beacon;
pub mod heartbeat;

pub mod dynamic_balance;
pub mod spam_guard;

pub mod phase_consensus;
pub mod phase_filters;
pub mod phase_integrity;
pub mod quorum;
pub mod sigpool;

pub mod ledger;
pub mod rcp_engine;
pub mod resonance;

// Безопасный AEAD (XChaCha20-Poly1305) — общий хелпер для модулей
pub mod crypto;
