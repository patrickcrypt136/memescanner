"""
🔬 MemeScanner Pro — Multi-Chain Meme Coin Analysis Bot
Chains: Ethereum, BSC, Solana
Data: GoPlus Security, DexScreener, Etherscan/BscScan, Moralis
AI: Groq (FREE — llama-3.3-70b-versatile)
"""

import os
import asyncio
import logging
import aiohttp
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    ContextTypes, MessageHandler, filters
)
from groq import Groq

# ── CONFIG ────────────────────────────────────────────────────────────────────
TELEGRAM_TOKEN    = os.getenv("TELEGRAM_TOKEN", "")
GROQ_API_KEY      = os.getenv("GROQ_API_KEY", "")
ETHERSCAN_API_KEY = os.getenv("ETHERSCAN_API_KEY", "")
BSCSCAN_API_KEY   = os.getenv("BSCSCAN_API_KEY", "")
MORALIS_API_KEY   = os.getenv("MORALIS_API_KEY", "")
ADMIN_TELEGRAM_ID = int(os.getenv("ADMIN_ID", "0"))


PREMIUM_USERS: set[int] = set()


# ── PAYMENT CONFIG ────────────────────────────────────────────────────────────
# Your wallet addresses — users pay here, then submit tx hash to verify
YOUR_SOL_WALLET  = os.getenv("SOL_WALLET", "JDDhNskvJVCAX1xLNioKSipThkPQktpnVjLf2yvWwrbj")
YOUR_ETH_WALLET  = os.getenv("ETH_WALLET", "0xcc9c1dac538b7e698c95baa0c66c345598634cc7")
PREMIUM_PRICE_USD = 14.99
PENDING_PAYMENTS: dict[int, str] = {}  # user_id -> expected chain

logging.basicConfig(format="%(asctime)s - %(levelname)s - %(message)s", level=logging.INFO)
logger = logging.getLogger(__name__)
ai_client = Groq(api_key=GROQ_API_KEY)

# Chain IDs for GoPlus
CHAIN_IDS = {"eth": "1", "bsc": "56", "sol": "solana"}

CHAIN_EXPLORERS = {
    "eth": {"name": "Ethereum", "api": "https://api.etherscan.io/api", "key": ETHERSCAN_API_KEY},
    "bsc": {"name": "BNB Chain", "api": "https://api.bscscan.com/api",  "key": BSCSCAN_API_KEY},
}


# ── HELPERS ───────────────────────────────────────────────────────────────────

async def get(url: str, params: dict = {}) -> dict | list | None:
    """Generic async GET with error handling."""
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, params=params, timeout=aiohttp.ClientTimeout(total=12)) as r:
                if r.status == 200:
                    return await r.json()
    except Exception as e:
        logger.warning(f"GET failed {url}: {e}")
    return None


def detect_chain(address: str) -> str:
    """Guess chain from address format."""
    if address.startswith("0x") and len(address) == 42:
        return "eth"   # Could be ETH or BSC — we'll check both
    return "sol"


# ── DATA FETCHERS ─────────────────────────────────────────────────────────────

async def fetch_goplus_security(address: str, chain: str) -> dict:
    """
    Token Sniffer API — contract security checks.
    Free, no key needed. Covers mintable, blacklist, ownership, open source.
    Docs: https://tokensniffer.com/api/v2
    """
    # Token Sniffer only supports ETH/BSC — Solana handled by RugCheck separately
    chain_map = {"eth": "1", "bsc": "56"}
    chain_id = chain_map.get(chain)
    if not chain_id:
        # For Solana, fetch from RugCheck and map to our format
        data = await fetch_rugcheck_solana(address)
        if not data:
            return {}
        risks = data.get("risks", [])
        risk_names = [r.get("name", "").lower() for r in risks if isinstance(r, dict)]
        score = data.get("score", 0)
        # RugCheck score: higher = riskier (opposite of TokenSniffer)
        # Convert to our format
        mint_disabled = data.get("tokenMeta", {}).get("mutable", True) is False
        top_holders = data.get("topHolders", [])
        return {
            "is_honeypot": "unknown",
            "buy_tax": "N/A (Solana)",
            "sell_tax": "N/A (Solana)",
            "is_mintable": "0" if mint_disabled else "1",
            "is_blacklisted": "1" if any("freeze" in r for r in risk_names) else "0",
            "owner_address": data.get("creator", "unknown"),
            "is_open_source": "unknown",
            "can_take_back_ownership": "unknown",
            "hidden_owner": "unknown",
            "trading_cooldown": "unknown",
            "is_anti_whale": "unknown",
            "score": f"{score} risk pts",
            "rugcheck_risks": [r.get("description", r.get("name","")) for r in risks[:3]],
        }

    try:
        url = f"https://tokensniffer.com/api/v2/tokens/{chain_id}/{address}"
        params = {"include_metrics": "1", "include_tests": "1"}
        data = await get(url, params)
        if not isinstance(data, dict):
            return {}

        # Map Token Sniffer fields to our standard format
        tests = data.get("tests", [])
        test_names = [t.get("name", "") for t in tests if isinstance(t, dict)]

        is_mintable   = "1" if any("mint" in t.lower() for t in test_names) else "0"
        has_blacklist = "1" if any("blacklist" in t.lower() for t in test_names) else "0"
        is_open_source = "1" if data.get("is_source_available", False) else "0"

        # Owner / renounce info
        owner = data.get("owner_address", "")
        is_renounced = owner in ["0x0000000000000000000000000000000000000000", "", None]

        return {
            "is_honeypot": "unknown",   # handled by honeypot.is
            "buy_tax": data.get("buy_fee", "unknown"),
            "sell_tax": data.get("sell_fee", "unknown"),
            "is_mintable": is_mintable,
            "is_blacklisted": has_blacklist,
            "owner_address": owner,
            "is_open_source": is_open_source,
            "can_take_back_ownership": "0" if is_renounced else "1",
            "hidden_owner": "unknown",
            "trading_cooldown": "unknown",
            "is_anti_whale": "unknown",
            "score": data.get("score", "N/A"),
        }
    except Exception as e:
        logger.warning(f"Token Sniffer error: {e}")
        return {}


async def fetch_dexscreener(address: str) -> dict | None:
    """DexScreener — price, volume, liquidity, pair info. Free, no key."""
    data = await get(f"https://api.dexscreener.com/latest/dex/tokens/{address}")
    if data and data.get("pairs"):
        pairs = data["pairs"]
        # Best pair = highest liquidity USD
        return max(pairs, key=lambda p: float(p.get("liquidity", {}).get("usd", 0) or 0))
    return None


async def fetch_honeypot_is(address: str, chain: str) -> dict:
    """
    Honeypot.is API — dedicated honeypot detection. Free, no key needed.
    More accurate than GoPlus for honeypot specifically.
    """
    # honeypot.is uses chain IDs
    chain_map = {"eth": "1", "bsc": "56"}
    chain_id = chain_map.get(chain)
    if not chain_id:
        return {}  # Solana not supported by honeypot.is
    try:
        url = f"https://api.honeypot.is/v2/IsHoneypot"
        data = await get(url, {"address": address, "chainID": chain_id})
        if not isinstance(data, dict):
            return {}
        return data
    except Exception as e:
        logger.warning(f"Honeypot.is error: {e}")
        return {}


async def fetch_rugcheck_solana(address: str) -> dict:
    """
    RugCheck API — Solana token security. Free, no key needed.
    Covers mint authority, freeze authority, top holders, risk score.
    Docs: https://api.rugcheck.xyz
    """
    try:
        url = f"https://api.rugcheck.xyz/v1/tokens/{address}/report/summary"
        data = await get(url)
        if not isinstance(data, dict):
            return {}
        return data
    except Exception as e:
        logger.warning(f"RugCheck error: {e}")
        return {}


async def fetch_top_holders(address: str, chain: str) -> list:
    """
    Moralis API — top token holders.
    Free tier: 40,000 CU/month. Get key: https://moralis.io
    """
    if chain == "sol":
        return []  # Moralis Solana holder endpoint differs — skip for now

    chain_name = "eth" if chain == "eth" else "bsc"
    url = f"https://deep-index.moralis.io/api/v2.2/erc20/{address}/owners"
    headers = {"X-API-Key": MORALIS_API_KEY}
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(
                url,
                params={"chain": chain_name, "limit": "10"},
                headers=headers,
                timeout=aiohttp.ClientTimeout(total=12)
            ) as r:
                if r.status == 200:
                    data = await r.json()
                    return data.get("result", [])
    except Exception as e:
        logger.warning(f"Moralis holders error: {e}")
    return []


async def fetch_deployer_wallet(address: str, chain: str) -> dict:
    """
    Etherscan/BscScan — find deployer wallet and recent transactions.
    Free API key: https://etherscan.io/register (BSCScan same login)
    """
    if chain not in CHAIN_EXPLORERS:
        return {}

    cfg = CHAIN_EXPLORERS[chain]
    # Get contract creation tx
    data = await get(cfg["api"], {
        "module": "contract",
        "action": "getcontractcreation",
        "contractaddresses": address,
        "apikey": cfg["key"]
    })

    deployer = None
    if data and isinstance(data.get("result"), list) and len(data["result"]) > 0:
        result_item = data["result"][0]
        if isinstance(result_item, dict):
            deployer = result_item.get("contractCreator")

    # Get deployer's last 10 transactions
    txs = []
    if deployer:
        tx_data = await get(cfg["api"], {
            "module": "account",
            "action": "tokentx",
            "address": deployer,
            "contractaddress": address,
            "sort": "desc",
            "offset": "10",
            "page": "1",
            "apikey": cfg["key"]
        })
        if tx_data and tx_data.get("result"):
            txs = tx_data["result"][:10]

    return {"deployer": deployer, "recent_txs": txs}


async def fetch_liquidity_lock(pair_address: str) -> str:
    """Check DexScreener for liquidity info (lock data is approximate)."""
    # Full lock checks require Team.Finance or Unicrypt APIs
    # This is a placeholder that returns a note
    return "Check manually: https://app.unicrypt.network or https://team.finance"


# ── ANALYSIS ENGINE ───────────────────────────────────────────────────────────

def build_analysis_summary(
    address: str,
    chain: str,
    goplus: dict,
    dex_pair: dict | None,
    holders: list,
    deployer_info: dict,
    honeypot_data: dict = {}
) -> dict:
    """Compile all raw data into a structured summary for Claude."""

    # Ensure all inputs are correct types
    if not isinstance(goplus, dict):
        goplus = {}
    if not isinstance(deployer_info, dict):
        deployer_info = {}
    if not isinstance(holders, list):
        holders = []
    if not isinstance(honeypot_data, dict):
        honeypot_data = {}

    # Honeypot.is result (more reliable than GoPlus for this)
    hp_result = honeypot_data.get("honeypotResult", {})
    hp_is_honeypot = hp_result.get("isHoneypot", None) if isinstance(hp_result, dict) else None
    hp_reason = hp_result.get("honeypotReason", "") if isinstance(hp_result, dict) else ""

    # Simulation data from honeypot.is
    sim = honeypot_data.get("simulationResult", {})
    hp_buy_tax = sim.get("buyTax", None) if isinstance(sim, dict) else None
    hp_sell_tax = sim.get("sellTax", None) if isinstance(sim, dict) else None

    # Cross-check: flag honeypot if EITHER source says yes
    goplus_honeypot = str(goplus.get("is_honeypot", "")) == "1"
    final_honeypot = "1" if (goplus_honeypot or hp_is_honeypot is True) else ("0" if hp_is_honeypot is False else "unknown")

    # Contract safety flags
    safety = {
        "is_honeypot": final_honeypot,
        "honeypot_reason": hp_reason if hp_reason else "N/A",
        "honeypot_source": "Honeypot.is + GoPlus" if hp_is_honeypot is not None else "GoPlus only",
        "buy_tax": goplus.get("buy_tax", "unknown"),
        "sell_tax": goplus.get("sell_tax", "unknown"),
        "is_mintable": goplus.get("is_mintable", "unknown"),
        "has_blacklist": goplus.get("is_blacklisted", "unknown"),
        "owner_address": goplus.get("owner_address", "unknown"),
        "ownership_renounced": goplus.get("owner_address", "0x0") in ["0x0000000000000000000000000000000000000000", "", None],
        "is_open_source": goplus.get("is_open_source", "unknown"),
        "can_take_back_ownership": goplus.get("can_take_back_ownership", "unknown"),
        "hidden_owner": goplus.get("hidden_owner", "unknown"),
        "trading_cooldown": goplus.get("trading_cooldown", "unknown"),
        "is_anti_whale": goplus.get("is_anti_whale", "unknown"),
    }

    # Market data
    market = {}
    if dex_pair:
        market = {
            "price_usd": dex_pair.get("priceUsd"),
            "price_change_5m": dex_pair.get("priceChange", {}).get("m5"),
            "price_change_1h": dex_pair.get("priceChange", {}).get("h1"),
            "price_change_6h": dex_pair.get("priceChange", {}).get("h6"),
            "price_change_24h": dex_pair.get("priceChange", {}).get("h24"),
            "volume_24h": dex_pair.get("volume", {}).get("h24"),
            "liquidity_usd": dex_pair.get("liquidity", {}).get("usd"),
            "market_cap": dex_pair.get("marketCap"),
            "fdv": dex_pair.get("fdv"),
            "buys_24h": dex_pair.get("txns", {}).get("h24", {}).get("buys"),
            "sells_24h": dex_pair.get("txns", {}).get("h24", {}).get("sells"),
            "dex": dex_pair.get("dexId"),
            "chain": dex_pair.get("chainId"),
            "pair_age_hours": None,  # could calc from pairCreatedAt
            "pair_url": dex_pair.get("url"),
        }

    # Holder distribution
    holder_summary = []
    total_supply_pct = 0
    for h in holders[:10]:
        pct = float(h.get("percentage_relative_to_total_supply", 0) or 0)
        total_supply_pct += pct
        holder_summary.append({
            "address": h.get("owner_address", "?")[:10] + "...",
            "pct": round(pct, 2)
        })

    # Deployer info
    dev = {
        "deployer_wallet": deployer_info.get("deployer"),
        "recent_dev_txs": len(deployer_info.get("recent_txs", [])),
        "dev_sells_detected": any(
            tx.get("from", "").lower() == deployer_info.get("deployer", "").lower()
            for tx in deployer_info.get("recent_txs", [])
        )
    }

    return {
        "address": address,
        "chain": chain.upper(),
        "contract_safety": safety,
        "market_data": market,
        "top_holders": holder_summary,
        "top_10_concentration_pct": round(total_supply_pct, 2),
        "developer": dev,
    }


def run_ai_analysis(summary: dict, is_premium: bool) -> str:
    """Send compiled data to Claude for final analysis."""
    if not is_premium:
        return (
            "🔒 *AI Analysis locked for free users.*\n\n"
            "Premium users get:\n"
            "• Risk score (1–10)\n"
            "• Safe / Moderate / High Risk / Scam verdict\n"
            "• Dev behavior analysis\n"
            "• Whale & insider flags\n"
            "• Bullish & bearish signals\n\n"
            "👉 /premium to upgrade"
        )

    prompt = f"""You are an expert on-chain meme coin analyst and rug-pull detection engine.

Analyze this token data objectively. Be skeptical. Hype ≠ legitimacy.

TOKEN DATA:
{summary}

Respond in EXACTLY this format:

RISK SCORE: X/10  (10 = safest, 1 = likely scam)
VERDICT: [SAFE ✅ / MODERATE RISK ⚠️ / HIGH RISK 🚨 / LIKELY SCAM ☠️]

CONTRACT FLAGS:
• [List key contract risks or green flags, 3–5 bullets]

DEV BEHAVIOR:
• [Deployer wallet activity — dumping? holding? burning?]

HOLDER DISTRIBUTION:
• [Is supply concentrated? Whale risk?]

MARKET SIGNALS:
• [Volume/liquidity health, buy/sell ratio, price action]

🟢 BULLISH SIGNALS:
• [2–3 positives if any]

🔴 BEARISH / RED FLAGS:
• [2–3 risks]

VERDICT SUMMARY:
[2–3 sentence conclusion. Is it worth trading? What's the #1 risk?]

Be data-driven. If data is missing, say so — don't fabricate."""

    try:
        response = ai_client.chat.completions.create(
            model="llama-3.3-70b-versatile",   # Free, fast, powerful
            max_tokens=700,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.choices[0].message.content
    except Exception as e:
        logger.error(f"Groq error: {e}")
        return "⚠️ AI analysis temporarily unavailable. Try again in a moment."


# ── MESSAGE FORMATTERS ────────────────────────────────────────────────────────

def format_report(summary: dict, ai_analysis: str) -> str:
    chain = summary["chain"]
    addr = summary["address"]
    short_addr = addr[:6] + "..." + addr[-4:]
    safety = summary["contract_safety"]
    market = summary.get("market_data", {})
    dev = summary.get("developer", {})
    holders = summary.get("top_holders", [])
    concentration = summary.get("top_10_concentration_pct", "?")

    # Safety icons
    hp_val = str(safety.get("is_honeypot", "unknown"))
    hp_reason = safety.get("honeypot_reason", "")
    hp_source = safety.get("honeypot_source", "")
    if hp_val == "1":
        honeypot = f"🚨 YES ({hp_reason})" if hp_reason and hp_reason != "N/A" else "🚨 YES"
    elif hp_val == "0":
        honeypot = f"✅ NO ({hp_source})"
    elif chain == "SOL":
        honeypot = "ℹ️ N/A (use RugCheck risks below)"
    else:
        honeypot = "❓ Unknown"
    mintable  = "⚠️ YES" if str(safety.get("is_mintable")) == "1" else "✅ NO" if str(safety.get("is_mintable")) == "0" else "❓"
    blacklist = "⚠️ YES" if str(safety.get("has_blacklist")) == "1" else "✅ NO" if str(safety.get("has_blacklist")) == "0" else "❓"
    renounced = "✅ YES" if safety.get("ownership_renounced") else "⚠️ NO"
    open_src  = "✅ YES" if str(safety.get("is_open_source")) == "1" else "⚠️ NO"

    buy_tax  = safety.get("buy_tax", "?")
    sell_tax = safety.get("sell_tax", "?")

    # Market
    price    = market.get("price_usd", "N/A")
    ch24     = market.get("price_change_24h", "N/A")
    vol24    = market.get("volume_24h", "N/A")
    liq      = market.get("liquidity_usd", "N/A")
    mcap     = market.get("market_cap", "N/A")
    buys     = market.get("buys_24h", "?")
    sells    = market.get("sells_24h", "?")
    dex_url  = market.get("pair_url", "")

    try: vol24 = f"${float(vol24):,.0f}"
    except: pass
    try: liq = f"${float(liq):,.0f}"
    except: pass
    try: mcap = f"${float(mcap):,.0f}"
    except: pass
    try: ch24_str = f"{float(ch24):+.2f}%"
    except: ch24_str = str(ch24)

    # Holder list
    holder_lines = "\n".join(
        f"  {i+1}. `{h['address']}` — {h['pct']}%"
        for i, h in enumerate(holders[:5])
    ) or "  Data unavailable"

    report = (
        f"🔬 *TOKEN SCAN REPORT*\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"⛓ Chain: `{chain}`\n"
        f"📝 Address: `{short_addr}`\n\n"

        f"🛡 *CONTRACT SAFETY*\n"
        f"• Honeypot: {honeypot}\n"
        f"• Mintable: {mintable}\n"
        f"• Blacklist: {blacklist}\n"
        f"• Ownership Renounced: {renounced}\n"
        f"• Open Source: {open_src}\n"
        f"• Buy Tax: `{buy_tax}%` | Sell Tax: `{sell_tax}%`\n\n"

        f"💰 *MARKET DATA*\n"
        f"• Price: `${price}`\n"
        f"• 24h Change: `{ch24_str}`\n"
        f"• 24h Volume: `{vol24}`\n"
        f"• Liquidity: `{liq}`\n"
        f"• Market Cap: `{mcap}`\n"
        f"• Buys/Sells (24h): `{buys}` / `{sells}`\n\n"

        f"👥 *TOP HOLDERS*\n"
        f"• Top 10 hold: `{concentration}%` of supply\n"
        f"{holder_lines}\n\n"

        f"👨‍💻 *DEV WALLET*\n"
        f"• Deployer: `{str(dev.get('deployer_wallet', 'Unknown'))[:20]}...`\n"
        f"• Dev sells detected: {'⚠️ YES' if dev.get('dev_sells_detected') else '✅ None detected'}\n\n"

        f"━━━━━━━━━━━━━━━━━━━━\n"
        f"🤖 *AI ANALYSIS*\n"
        f"{ai_analysis}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n"
    )

    if dex_url:
        report += f"🔗 [View on DexScreener]({dex_url})\n"

    report += "\n⚠️ _DYOR. Not financial advice. Meme coins are high risk._"
    return report


# ── PAYMENT VERIFICATION ─────────────────────────────────────────────────────

async def verify_sol_payment(tx_hash: str, payer_id: int) -> tuple[bool, str]:
    """Verify a Solana payment using Solscan public API. No key needed."""
    try:
        url = f"https://public-api.solscan.io/transaction/{tx_hash}"
        data = await get(url)
        if not isinstance(data, dict):
            return False, "Transaction not found."

        status = data.get("status", "")
        if status != "Success":
            return False, f"Transaction status: {status}. Must be successful."

        # Check it was sent to your wallet
        instructions = data.get("parsedInstruction", [])
        for ix in instructions:
            dest = ix.get("params", {}).get("destination", "")
            amount_raw = ix.get("params", {}).get("amount", 0)
            if dest.lower() == YOUR_SOL_WALLET.lower():
                amount_sol = float(amount_raw) / 1e9
                # Rough SOL price check — just verify something was sent
                if amount_sol > 0.01:  # at least 0.01 SOL
                    return True, f"✅ Payment verified! {amount_sol:.4f} SOL received."
        return False, "Payment not found to your wallet address. Check the tx hash."
    except Exception as e:
        logger.error(f"SOL verify error: {e}")
        return False, "Error verifying transaction. Try again."


async def verify_eth_payment(tx_hash: str) -> tuple[bool, str]:
    """Verify ETH/BSC payment using Etherscan. Needs Etherscan key."""
    try:
        url = "https://api.etherscan.io/api"
        data = await get(url, {
            "module": "proxy",
            "action": "eth_getTransactionByHash",
            "txhash": tx_hash,
            "apikey": ETHERSCAN_API_KEY
        })
        if not isinstance(data, dict) or not data.get("result"):
            return False, "Transaction not found."

        tx = data["result"]
        to_addr = tx.get("to", "").lower()
        value_wei = int(tx.get("value", "0x0"), 16)
        value_eth = value_wei / 1e18

        if to_addr == YOUR_ETH_WALLET.lower() and value_eth > 0.001:
            return True, f"✅ Payment verified! {value_eth:.6f} ETH received."
        return False, "Payment not sent to your wallet or amount too low."
    except Exception as e:
        logger.error(f"ETH verify error: {e}")
        return False, "Error verifying transaction."


# ── BOT HANDLERS ──────────────────────────────────────────────────────────────

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    is_premium = user.id in PREMIUM_USERS
    tier = "⭐ Premium" if is_premium else "🆓 Free"

    keyboard = [
        [InlineKeyboardButton("🔬 Scan a Token", callback_data="scan_prompt")],
        [InlineKeyboardButton("🔥 Trending", callback_data="trending")],
        [InlineKeyboardButton("💎 Go Premium — Pay with Crypto", callback_data="pay_info")],
        [InlineKeyboardButton("❓ How to Use", callback_data="howto")],
    ]

    await update.message.reply_text(
        f"👋 *Welcome, {user.first_name}!*\n\n"
        f"I'm *MemeScanner Pro* 🔬\n"
        f"Multi-chain meme coin analysis powered by Claude AI.\n\n"
        f"Your tier: {tier}\n\n"
        f"Paste any token contract address to get:\n"
        f"• Honeypot & rug detection\n"
        f"• Dev wallet tracking\n"
        f"• Holder distribution\n"
        f"• AI risk score & verdict\n",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode="Markdown"
    )


async def scan_address(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle direct address paste or /scan command."""
    user = update.effective_user
    is_premium = user.id in PREMIUM_USERS

    # Get address from command args or message text
    if context.args:
        parts = context.args
        address = parts[0]
        chain = parts[1].lower() if len(parts) > 1 else "eth"
    else:
        text = update.message.text.strip()
        # Auto-detect address pasted directly
        parts = text.split()
        address = parts[0]
        chain = parts[1].lower() if len(parts) > 1 else detect_chain(address)

    if not address:
        await update.message.reply_text(
            "❓ Please provide a contract address.\n"
            "Example: `/scan 0xabc123... eth`\n"
            "Chains: `eth`, `bsc`, `sol`",
            parse_mode="Markdown"
        )
        return

    chain = chain if chain in ["eth", "bsc", "sol"] else "eth"
    status_msg = await update.message.reply_text(
        f"🔍 Scanning `{address[:10]}...` on *{chain.upper()}*\n\n"
        f"⏳ Fetching: contract security...",
        parse_mode="Markdown"
    )

    try:
        # Fetch all data in parallel
        goplus_task    = fetch_goplus_security(address, chain)
        dex_task       = fetch_dexscreener(address)
        holders_task   = fetch_top_holders(address, chain)
        deployer_task  = fetch_deployer_wallet(address, chain)
        honeypot_task  = fetch_honeypot_is(address, chain)

        await status_msg.edit_text(
            f"🔍 Scanning `{address[:10]}...` on *{chain.upper()}*\n\n"
            f"⏳ Fetching: holders & dev wallet...",
            parse_mode="Markdown"
        )

        goplus, dex_pair, holders, deployer_info, honeypot_data = await asyncio.gather(
            goplus_task, dex_task, holders_task, deployer_task, honeypot_task
        )

        await status_msg.edit_text(
            f"🔍 Scanning `{address[:10]}...` on *{chain.upper()}*\n\n"
            f"⏳ Running AI analysis...",
            parse_mode="Markdown"
        )

        # Debug: log what we got back
        logger.info(f"GoPlus type: {type(goplus)} | value: {str(goplus)[:200]}")
        logger.info(f"DexPair type: {type(dex_pair)}")
        logger.info(f"Holders type: {type(holders)}")
        logger.info(f"Deployer type: {type(deployer_info)}")

        # Build summary
        summary = build_analysis_summary(address, chain, goplus, dex_pair, holders, deployer_info, honeypot_data)

        # Run AI
        ai_analysis = run_ai_analysis(summary, is_premium)

        # Format and send report
        report = format_report(summary, ai_analysis)

        await status_msg.delete()
        await update.message.reply_text(
            report,
            parse_mode="Markdown",
            disable_web_page_preview=True
        )

    except Exception as e:
        import traceback
        err_detail = traceback.format_exc()
        logger.error(f"Scan error: {e}\n{err_detail}")
        await status_msg.edit_text(
            f"❌ Error: `{str(e)[:200]}`\n\n"
            f"Format: `/scan <address> <chain>`\n"
            f"Example: `/scan 0xabc... bsc`",
            parse_mode="Markdown"
        )


async def trending_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.message or update.callback_query.message
    await msg.reply_text("⏳ Fetching trending coins...")

    data = await get("https://api.coingecko.com/api/v3/search/trending")
    if not data:
        await msg.reply_text("❌ Could not fetch trending data.")
        return

    coins = data.get("coins", [])[:7]
    text = "🔥 *CoinGecko Trending Now*\n━━━━━━━━━━━━\n\n"

    for i, c in enumerate(coins):
        item = c["item"]
        name = item.get("name")
        sym  = item.get("symbol", "").upper()
        rank = item.get("market_cap_rank", "N/A")
        score = item.get("score", 0)
        text += f"{i+1}. *{name}* (${sym}) — Rank #{rank}\n"

    text += "\n💡 To scan a token, paste its contract address or use:\n`/scan <address> <chain>`"
    await msg.reply_text(text, parse_mode="Markdown")


async def premium_info(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.message or update.callback_query.message
    user = update.effective_user

    if user.id in PREMIUM_USERS:
        await msg.reply_text("✅ You're already *Premium*! Full AI analysis unlocked 🚀", parse_mode="Markdown")
        return

    await msg.reply_text(
        "💎 *MemeScanner Pro — Premium*\n\n"
        "*Free tier:*\n"
        "✅ Contract safety check\n"
        "✅ Market data (price, volume, liquidity)\n"
        "✅ Top holders view\n"
        "✅ Dev wallet info\n"
        "🔒 AI risk score & verdict\n"
        "🔒 Detailed AI analysis\n\n"
        "*Premium tier ($14.99/month):*\n"
        "✅ Everything above\n"
        "✅ AI Risk Score (1–10)\n"
        "✅ SAFE / SCAM verdict\n"
        "✅ Dev behavior analysis\n"
        "✅ Whale & insider flags\n"
        "✅ Bull/bear signal breakdown\n"
        "✅ Priority support\n\n"
        "💰 Pay via USDT (TRC20/BSC) or PayPal\n"
        "📩 Contact: @YourUsername to activate\n\n"
        "_Your Telegram ID will be activated within 1 hour of payment._",
        parse_mode="Markdown"
    )


async def howto(update: Update, context: ContextTypes.DEFAULT_TYPE):
    msg = update.message or update.callback_query.message
    await msg.reply_text(
        "📖 *How to Use MemeScanner Pro*\n\n"
        "1️⃣ Find a token's contract address\n"
        "   (from DexScreener, CoinGecko, or Telegram groups)\n\n"
        "2️⃣ Paste the address directly in chat, or use:\n"
        "   `/scan <address> <chain>`\n\n"
        "3️⃣ Specify the chain:\n"
        "   • `eth` — Ethereum\n"
        "   • `bsc` — BNB Chain\n"
        "   • `sol` — Solana\n\n"
        "📌 *Example:*\n"
        "`/scan 0x6982508145454ce325ddbe47a25d4ec3d2311933 eth`\n\n"
        "You can also just paste the address and chain:\n"
        "`0x6982... bsc`\n\n"
        "⚠️ _Always DYOR. This bot helps — it doesn't guarantee._",
        parse_mode="Markdown"
    )


async def message_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Handle raw address pastes."""
    text = update.message.text.strip()
    # Detect if it looks like an address
    if (text.startswith("0x") and len(text.split()[0]) == 42) or \
       (len(text.split()[0]) in [43, 44] and not text.startswith("/")):
        await scan_address(update, context)
    else:
        await update.message.reply_text(
            "💬 I'm a token scanner!\n"
            "Paste a contract address or use /scan\n"
            "Type /help for commands.",
        )


async def button_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    if query.data == "pay_info":
        await pay_command(update, context)
        return
    if query.data == "trending":
        await trending_command(update, context)
    elif query.data == "premium_info":
        await premium_info(update, context)
    elif query.data == "howto":
        await howto(update, context)
    elif query.data == "scan_prompt":
        await query.message.reply_text(
            "📋 *Paste a contract address to scan!*\n\n"
            "Format: `<address> <chain>`\n\n"
            "Examples:\n"
            "`0x6982508145454ce325ddbe47a25d4ec3d2311933 eth`\n"
            "`0xcc42724c6683b7e57334c4e856f4c9965ed682bd bsc`\n\n"
            "Or use the command:\n"
            "`/scan <address> <chain>`",
            parse_mode="Markdown"
        )


async def pay_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if user.id in PREMIUM_USERS:
        await update.message.reply_text("You are already Premium!")
        return
    price = str(PREMIUM_PRICE_USD)
    lines = [
        "💎 *Upgrade to Premium — $" + price + "/month*",
        "",
        "Send payment to either wallet:",
        "",
        "🟣 *Solana (SOL):*",
        "`" + YOUR_SOL_WALLET + "`",
        "",
        "🔵 *Ethereum (ETH):*",
        "`" + YOUR_ETH_WALLET + "`",
        "",
        "After paying, send your transaction hash:",
        "`/verify <tx_hash> <sol or eth>`",
        "",
        "Example:",
        "`/verify 5xK3abc...xyz sol`",
        "",
        "_Your account will be activated automatically._"
    ]
    await update.message.reply_text("\n".join(lines), parse_mode="Markdown")


async def verify_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    if user.id in PREMIUM_USERS:
        await update.message.reply_text("You are already Premium!")
        return
    if not context.args or len(context.args) < 2:
        await update.message.reply_text(
            "Usage: /verify <tx_hash> <sol or eth>",
            parse_mode="Markdown"
        )
        return
    tx_hash = context.args[0]
    chain = context.args[1].lower()
    await update.message.reply_text("Verifying your payment on-chain...")
    if chain == "sol":
        success, msg = await verify_sol_payment(tx_hash, user.id)
    elif chain in ["eth", "bsc"]:
        success, msg = await verify_eth_payment(tx_hash)
    else:
        await update.message.reply_text("Chain must be sol or eth")
        return
    if success:
        PREMIUM_USERS.add(user.id)
        welcome = msg + "\n\n🎉 *Welcome to Premium, " + user.first_name + "!* Full AI analysis is now unlocked."
        await update.message.reply_text(welcome, parse_mode="Markdown")
    else:
        await update.message.reply_text("Payment failed: " + msg + " Need help? Contact @YourUsername")




async def debug_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Admin only: show raw Token Sniffer response for an address."""
    if update.effective_user.id != ADMIN_TELEGRAM_ID:
        return
    if not context.args:
        await update.message.reply_text("Usage: /debug <address>")
        return
    address = context.args[0]
    import json
    raw = await fetch_goplus_security(address, "eth")
    text = json.dumps(raw, indent=2)[:3000]
    msg = "Raw data: " + text
    await update.message.reply_text(msg)


async def add_premium_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_TELEGRAM_ID:
        return
    if not context.args:
        await update.message.reply_text("Usage: /addpremium <user_id>")
        return
    try:
        uid = int(context.args[0])
        PREMIUM_USERS.add(uid)
        await update.message.reply_text(f"✅ User {uid} upgraded to Premium!")
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID.")


async def remove_premium_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if update.effective_user.id != ADMIN_TELEGRAM_ID:
        return
    if not context.args:
        await update.message.reply_text("Usage: /removepremium <user_id>")
        return
    try:
        uid = int(context.args[0])
        PREMIUM_USERS.discard(uid)
        await update.message.reply_text(f"✅ User {uid} removed from Premium.")
    except ValueError:
        await update.message.reply_text("❌ Invalid user ID.")


# ── MAIN ──────────────────────────────────────────────────────────────────────

def main():
    app = Application.builder().token(TELEGRAM_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("help", howto))
    app.add_handler(CommandHandler("scan", scan_address))
    app.add_handler(CommandHandler("trending", trending_command))
    app.add_handler(CommandHandler("premium", premium_info))
    app.add_handler(CommandHandler("pay", pay_command))
    app.add_handler(CommandHandler("verify", verify_command))
    app.add_handler(CommandHandler("debug", debug_cmd))
    app.add_handler(CommandHandler("addpremium", add_premium_cmd))
    app.add_handler(CommandHandler("removepremium", remove_premium_cmd))
    app.add_handler(CallbackQueryHandler(button_handler))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, message_handler))

    logger.info("🔬 MemeScanner Pro is running...")
    app.run_polling(drop_pending_updates=True)


if __name__ == "__main__":
    main()