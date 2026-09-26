# W3K Worker v218.63 — System Audit

ဖိုင် — `W3K-worker-v218.63.js` (25,351 lines · Cloudflare Worker + D1 + Telegram Bot + Admin Dashboard)
စစ်ဆေးသည့်နေ့ — 2026-09-26
Line နံပါတ်များသည် upload လုပ်ထားသော v218.63 ဖိုင်အတိုင်း ဖြစ်သည်။

စစ်ဆေးခဲ့သည့် နယ်ပယ် — routing/auth (`fetch`), admin login + Telegram 2FA, Google OAuth, CSRF/replay guard,
Telegram webhook + duplicate guard, `handleCallback` ခွင့်ပြုချက်, purchase (`executePurchase`, `deductBalance`,
`revertBalance`), deposit (receipt intake, OCR, auto-approve, approve/reject/reverse), withdrawal, refund/warranty,
reseller reward, backup, Mini App (`/delivery/data`), dashboard XSS sinks, SQL injection။

---

## အကျဉ်းချုပ်

| # | Severity | ခေါင်းစဉ် | Line |
|---|---|---|---|
| 1 | 🔴 Critical | Auto-Approve သည် customer ပို့သော screenshot ကိုသာ ယုံသည် — ပြေစာအတုဖြင့် ငွေရနိုင်သည် | 12193, 11147 |
| 2 | 🔴 High | `deliverOrder` ↔ Customer "Cancel & Refund" race — ပစ္စည်းရော ငွေရော ရနိုင်သည် | 11774–11803, 12984 |
| 3 | 🔴 High | `reverseAutoDeposit` atomic မဖြစ် — ↩️ ကို ၂ ခါနှိပ်လျှင် ၂ ခါ နှုတ်သည် | 12254–12262 |
| 4 | 🔴 High | Telegram "poison update" — error တစ်ခုက 503 ကို အဆုံးမရှိ ပြန်ပို့စေသည် | 4266, 14331 |
| 5 | 🟠 High | Daily backup ထဲ `orders.key_data` (plaintext key/account) နှင့် customer PII ပါသွားသည် | 14152 |
| 6 | 🟠 Medium | `deleteSalesOrder` — partial refund ပြီးသား order ကို ဖျက်လျှင် ငွေအပြည့် ထပ်ပြန်ပေးသည် | 11833, 11851 |
| 7 | 🟠 Medium | D1 `batch()` သည် "0 rows changed" တွင် rollback မလုပ် — "မပြောင်းပါ" ဟု မှားပြောသည် | 12096, 11868 |
| 8 | 🟠 Medium | Receipt / photo upload rate-limit မရှိ — OpenAI cost + admin spam | 11195, 11180, 5258 |
| 9 | 🟡 Medium | `approveDeposit` credit ကို registry စစ်မီ ပေါင်းပြီးမှ compensate လုပ်သည် | 12306–12352 |
| 10 | 🟡 Medium | USDT one-tap approve (`da_`) သည် customer TXID ကို on-chain မစစ်ဘဲ ယုံသည် | 13086 |
| 11 | 🟡 Low-Med | `revertBalance` idempotent မဟုတ် (random ref) | 10017 |
| 12 | 🟡 Low | Auto-approve daily cap TOCTOU race | 12239 |
| 13 | 🟡 Low | Withdrawal — proof ပို့ fail ဖြစ်ပြီး (`failed`) Reject လုပ်၍ရ → ငွေ ၂ ဆ ဖြစ်နိုင် | 4546 |
| 14 | 🟡 Low | Telegram retry တွင် non-idempotent message handler များ ထပ်အလုပ်လုပ်သည် | 4266 |
| 15 | ⚪ Low | initData 24h သက်တမ်း, admin API audit actor, server `esc()` `'` မ escape, dead code, backup window | 517, 1072, 12637, 14613 |

အကောင်းဘက် — auth/session (HMAC + epoch + allowlist re-check), Telegram login 2FA, CSRF (Sec-Fetch-Site),
replay nonce, webhook secret header, `deductBalance` idempotent op-id, deposit double-credit guard
(`deposit_credits` PK), refund guard table, Mini App initData verify + `chat_id` scope, SQL parameterisation,
dashboard `textContent`/`esc()` သုံးမှု — ဒါတွေက ခိုင်မာပါတယ်။ SQL injection / stored XSS အစစ် မတွေ့ပါ။

---

## 1. 🔴 Auto-Approve — ပြေစာအတု (forged receipt) ဖြင့် ငွေရနိုင်ခြင်း

**နေရာ** — `autoApproveDecision()` L12193, `intakeDepositReceipt()` L11124–11152

Auto-approve ဖွင့်ထားလျှင် (default max 100,000 / day 500,000) စည်းမျဉ်း ၆ ချက်လုံးသည် **customer ပို့သော ပုံ** ထဲက
စာသားကိုသာ AI vision ဖြင့် ဖတ်ပြီး စစ်သည် —

- amount — ပုံထဲက ဂဏန်း
- transaction no ≥ 8 လုံး + အရင် မသုံးဖူးရ — attacker က random နံပါတ်အသစ် ရေးရုံ
- receiver — ဆိုင်၏ ငွေလက်ခံနံပါတ်/အမည် (customer ကို ပြထားပြီးသား public info)
- wallet name, time gap — ပုံထဲက အချိန်ကို လက်ရှိအချိန် ရေးရုံ

KBZPay/Wave screenshot ကို edit လုပ်ထားသော ပုံ တစ်ပုံက စည်းမျဉ်းအားလုံး ကိုက်သည်။ Balance ဝင်တာနဲ့ digital key ကို
ချက်ချင်း ဝယ်နိုင်သဖြင့် `reverseAutoDeposit` ("balance လုံလောက်မှ ပြန်ရုပ်") က အလုပ်မဖြစ်တော့ပါ။
ထို့အပြင် ပုံထဲ စာရေး၍ vision model ကို prompt-inject လုပ်နိုင်သည် (ဥပမာ "Amount: 100,000")။

**ပြင်ရန်**
- Wallet/bank ၏ တကယ့် statement (merchant API, SMS/notification forward) နှင့် မတိုက်ဘဲ auto-credit မလုပ်ပါနှင့်။
- မဖြစ်မနေ ထားလိုလျှင် — manual approve ≥ N ကြိမ် ရှိပြီးသား user များသာ, amount cap ကို နိမ့်နိမ့်, auto-credit
  ငွေကို admin confirm မလုပ်မချင်း instant-delivery product ဝယ်ခွင့် မပေး (hold)။
- Default OFF ကို ဆက်ထားပါ။

## 2. 🔴 `deliverOrder` ↔ `pc_` Cancel & Refund race

**နေရာ** — `deliverOrder()` L11774–11803, callback `pc_` L12984 → `refundOrder()`

`deliverOrder` သည် key_data ကို သိမ်းပြီး status ကို `Processing` အတိုင်း ထားကာ Telegram ပို့သည် (စက္ကန့်အတော်ကြာ)။
ပို့ပြီးမှ `status='Completed' WHERE status='Processing'` ပြောင်းသည်။ ထိုကြားထဲ customer (ETA ကျော်ပြီးလျှင်) က
**Cancel & Refund** နှိပ်လျှင် `refundOrder` က `Processing` ကို မြင်၍ ငွေပြန်ပေးသည် → ပြီးမှ key message ရောက်သည်။
Customer သည် ပစ္စည်းရော ငွေရော ရသည်။ Admin ၂ ယောက် တပြိုင်နက် deliver လုပ်လျှင်လည်း delivery ၂ ခါ ပို့သည်။

**ပြင်ရန်** — ပို့မီ status ကို claim လုပ်ပါ —
```js
const saved = await env.DB.prepare(
  "UPDATE orders SET status='Delivering', key_data=?, note=? WHERE id=? AND status='Processing'"
).bind(payload, 'Delivery attempt pending', orderId).run();
// fail → status='DeliveryFailed' WHERE status='Delivering'
// ok   → status='Completed'      WHERE status='Delivering'
```
`refundOrder` သည် `Processing` ကိုသာ လက်ခံသဖြင့် အလိုလို ပိတ်သွားမည်။ (`markOrderDelivered` က `Delivering` ကို လက်ခံပြီးသား။)

## 3. 🔴 `reverseAutoDeposit` — double debit

**နေရာ** — L12254–12262

Balance နှုတ်ခြင်း (`UPDATE users`) နှင့် deposit status ပြောင်းခြင်းကို သီးခြား statement ၂ ခုဖြင့် လုပ်ပြီး deposit update
တွင် `AND status='approved'` guard မပါ။ ↩️ ကို ၂ ခါ (သို့ admin ၂ ယောက်) တပြိုင်နက် နှိပ်လျှင် ၂ ခုစလုံး status check
ကျော်ပြီး balance ကို ၂ ခါ နှုတ်သည်။

**ပြင်ရန်** — batch တစ်ခုတည်း၊ deposit ကို အရင် claim —
```js
const rs = await env.DB.batch([
  env.DB.prepare("UPDATE deposits SET status='rejected',updated=?,note='auto-approve reversed' WHERE id=? AND status='approved' AND EXISTS (SELECT 1 FROM users WHERE chat_id=? AND balance>=?)").bind(now, id, cid, amt),
  env.DB.prepare("UPDATE users SET balance=balance-? WHERE chat_id=? AND EXISTS (SELECT 1 FROM deposits WHERE id=? AND status='rejected' AND updated=?)").bind(amt, cid, id, now),
  /* ledger insert — same EXISTS guard */
]);
```

## 4. 🔴 Telegram poison update

**နေရာ** — webhook L14331 (`processedOk ? 200 : 503`), `registerTelegramUpdate()` L4266

v217.40 မှစ၍ handler error ဖြစ်လျှင် 503 ပြန်သည်။ Telegram က retry လုပ်သောအခါ status `failed` ကို takeover လုပ်ကာ
**attempt limit မရှိဘဲ** ပြန် run သည်။ Deterministic bug (ဥပမာ message shape မမျှော်လင့်ထားခြင်း) ရှိသော update
တစ်ခုသည် —
- 503 ကို အဆုံးမရှိ ပြန်ပို့ပြီး webhook queue ကို နှောင့်နှေးစေသည် (`pending_update_count` တက်)
- attempt တိုင်း customer ဆီ "⚠️ ယာယီစနစ်အခက်အခဲ" နှင့် admin ဆီ "🚨 Update error" ပို့သည် (spam)

**ပြင်ရန်** — `telegram_updates` တွင် `attempts` column ထည့်ပြီး ≥3 ကြိမ်ဆိုလျှင် `status='dead'` + HTTP 200 ပြန်ပါ။
Error notification ကို ပထမအကြိမ်တွင်သာ ပို့ပါ။

## 5. 🟠 Backup ထဲ plaintext key/credential နှင့် PII ပါခြင်း

**နေရာ** — `buildSafeBackup()` L14150–14172

Caption က "🔒 Sensitive key/credential data မပါပါ" ဟုဆိုသော်လည်း —
- `orders` table ကို filter မလုပ်ပါ → `key_data` (ပို့ပြီးသား key / account password) ပါသည်။ Vault ထဲ archive
  ပြီးသော `Completed` order များသာ ရှင်းသည်; `Paid` / `DeliveryFailed` / `Processing` နှင့် ၆၀ ရက်မပြည့်သေးသော
  row များ plaintext ကျန်သည်။ **`CREDENTIAL_SECRET` မထည့်ထားလျှင် vault အလုပ်မလုပ်၍ key အားလုံး backup ထဲ ပါသည်။**
- `orders.customer_details`, `orders.username`, `key_reports.reason/photo_id`, `cart_items`, `product_requests` —
  PII filter မရှိ။

**ပြင်ရန်** — `orders` ကိုလည်း `keys` နည်းတူ column allowlist ဖြင့် map ပါ (`key_data`, `customer_details`,
`delivery_media`, `username` ဖယ်)။ Filter ကို denylist အစား allowlist သို့ ပြောင်းပါ။

## 6. 🟠 `deleteSalesOrder` double refund

**နေရာ** — L11833, L11851

`restoreCharge = status==='Completed' && price>0` ဖြစ်ပြီး `price` အပြည့်ကို balance ထဲ ပြန်ထည့်သည်။
Partial refund (`refundCompletedOrder`, warranty refund) လုပ်ပြီးသား order သည် status `Completed` အတိုင်း ကျန်သဖြင့်
ဖျက်လျှင် ငွေအပြည့် ထပ်ဝင်သည် (ဥပမာ 10,000 order → 3,000 refund ပြီး → delete → 10,000 ထပ်ဝင် = 13,000)။
`order_refunds` row များကိုလည်း ဖျက်ပစ်၍ report မှ ပျောက်သည်။ Balance ledger entry လည်း မရေးပါ။

**ပြင်ရန်** — `restore = price - SUM(order_refunds.amount)`၊ ledger ထည့်ပါ၊ production data တွင် ဤ "Test" tool ကို
ပိတ်ထားရန် စဉ်းစားပါ။

## 7. 🟠 D1 batch rollback မှားယူဆချက်

**နေရာ** — `refundOrder()` L12093–12097, `deleteSalesOrder()` L11867–11870

D1 `batch()` သည် statement **error** ဖြစ်မှသာ rollback လုပ်သည်။ `changes === 0` ဖြစ်ရုံဖြင့် rollback မလုပ်ပါ။
- `refundOrder` — reward နှုတ်သည့် statement (`balance>=?`) က 0 rows ဖြစ်လျှင် order `Refunded`, refund ငွေ ဝင်ပြီး,
  reward `reversed` ဖြစ်ပြီးသားဖြစ်သော်လည်း "Refund Failed. စာရင်းကို မပြောင်းလဲဘဲထားပါသည်" ဟု ပြန်ပြောပြီး
  reward ငွေ မနှုတ်ရပါ။
- `deleteSalesOrder` — `mustChange` fail ဖြစ်လျှင်လည်း ကျန် statement များ commit ဖြစ်ပြီးသား။

**ပြင်ရန်** — `createWithdrawal`/`approveDeposit` ကဲ့သို့ နောက် statement များကို `EXISTS(...)` guard ဖြင့်
ချိတ်ပါ၊ သို့မဟုတ် fail ဖြစ်ပါက compensate လုပ်ပြီး message ကို မှန်အောင် ပြင်ပါ။

## 8. 🟠 Receipt upload rate-limit မရှိ

**နေရာ** — `saveSlip()` L11195, `openExtraDeposit()` L11180, `handleMessage` photo branch L5258

Deposit `pending` ဖြစ်နေစဉ် ပုံအသစ် ပို့တိုင်း deposit အသစ် ဖွင့်ပြီး OpenAI vision ကို ၁–၂ ကြိမ် ခေါ်ကာ admin group ဆီ
card ပို့သည်။ Per-chat limit မရှိသဖြင့် user တစ်ယောက်က ပုံရာချီ ပို့၍ OpenAI bill နှင့် admin group ကို spam လုပ်နိုင်သည်။

**ပြင်ရန်** — `rateLimit('slip:'+chat, 3, 10*60000)` + `durableRateLimit`၊ chat တစ်ခုလျှင် open pending deposit
အရေအတွက် ကန့်သတ်ပါ။

## 9. 🟡 `approveDeposit` — credit before registry check

**နေရာ** — L12319–12352

Transaction registry INSERT OR IGNORE မအောင်မြင်လျှင်လည်း batch ၏ ဒုတိယ/တတိယ statement က balance ကို ပေါင်းပြီးမှ
`compensateCredit()` ဖြင့် ပြန်နှုတ်သည်။ ကြားထဲ customer သုံးသွားနိုင်ပြီး compensate သည် `balance>=` မစစ်ပါ။
**ပြင်ရန်** — `deposit_credits` INSERT ကို `WHERE EXISTS (SELECT 1 FROM deposit_txn_registry WHERE txn_norm=? AND deposit_id=?)` ဖြင့် ချိတ်ပါ။

## 10. 🟡 USDT one-tap approve

**နေရာ** — `da_` callback L13086

USDT deposit တွင် `customer_txn` + `amount` ရှိလျှင် admin က တစ်ချက်နှိပ်ရုံဖြင့် approve ဖြစ်သည်။ TXID ကို
blockchain (TRC20 explorer API) ပေါ်တွင် amount/receiver/confirmations မစစ်ပါ။ Admin process မှားလျှင် TXID အတုဖြင့်
ငွေဝင်နိုင်သည်။ **ပြင်ရန်** — TronGrid/Tronscan ဖြင့် auto-verify, သို့မဟုတ် one-tap ကို ပိတ်၍ amount ရိုက်ခိုင်းပါ။

## 11. 🟡 `revertBalance` idempotent မဟုတ်

**နေရာ** — L10017

`rollbackRef` တွင် `Date.now()+Math.random()` ပါသဖြင့် တူညီသော rollback ကို ၂ ကြိမ်ခေါ်လျှင် ၂ ကြိမ် ငွေပြန်ပေးသည်။
`originalOp` မတွေ့လျှင်လည်း ဆက်ပေးသည်။ လက်ရှိ caller များက တစ်ကြိမ်သာ ခေါ်သော်လည်း ref ကို deterministic
(`'rb:'+safeRef`) ထားပြီး `financial_ops` guard ထည့်သင့်သည်။

## 12. 🟡 Auto-approve daily cap race

**နေရာ** — L12236–12240. `autoApprovedToday()` read → approve ကြားတွင် concurrent receipt များ cap ကျော်နိုင်သည်။
Durable counter (`UPDATE ... SET n=n+? WHERE n+?<=cap`) သုံးပါ။

## 13. 🟡 Withdrawal reject after failed proof

**နေရာ** — `rejectWithdrawal()` L4546

`proof_status='failed'` (ငွေလွှဲပြီး screenshot ပို့ရာ fail) ဖြစ်လျှင် Reject လုပ်၍ ရပြီး balance ပြန်ဝင်သည် — ငွေ KPay သို့
လွှဲပြီးသားဖြစ်နိုင်သည်။ `CUSTOMER_WITHDRAW_OPEN=false` ဖြစ်၍ လက်ရှိ risk နည်းသည်။ ပြန်ဖွင့်မည်ဆိုလျှင်
"paid" ကို proof နှင့် သီးခြား flag ထားပါ။

## 14. 🟡 Retry တွင် non-idempotent handler

**နေရာ** — L4266

Update ကို ပြန် run သောအခါ purchase (`purchase_intents`) နှင့် deposit approve ကသာ idempotent ဖြစ်သည်။
Receipt save (deposit အသစ်), live-support forward, product request စသည်တို့ ထပ်ဖြစ်နိုင်သည်။ #4 ပြင်လျှင် သက်သာမည်။

## 15. ⚪ Low / hygiene

- **initData 24h** (L517) — Mini App credential reveal အတွက် 1h လောက်သို့ လျှော့ပါ; `auth_date` မပါလျှင် reject ပါ။
- **Admin API audit** — `adjust`, `cashout`, `refund` စသည်တို့ log တွင် actor `'Admin'` သာ; `apiAdminId`
  (Google email/username) ကို ထည့်ပါ။
- **Server `esc()`** (L1072) — `'` မ escape; single-quoted attribute ထဲ မသုံးမိစေရန် `&#39;` ထည့်ပါ။
- **Dead code** — `handleCallback` L12637 `purchaseRoute && access.banned` သည် L12606 ကြောင့် ဘယ်တော့မှ မရောက်။
- **Backup schedule** (L14613) — `localMinutes <= 2` သည် cron ကို Myanmar 00:00–00:02 တွင် run မှသာ အလုပ်လုပ်သည်။
  Hourly `0 * * * *` (UTC) ဆိုလျှင် local :30 ဖြစ်၍ backup ဘယ်တော့မှ မပို့ပါ။ `lastBackupDate !== localDate`
  တစ်ခုတည်းဖြင့် စစ်ပါ။
- **MFA fatigue** — password သိသူက `/admin-login` ကို ၁ မိနစ် ၁၂ ကြိမ်အထိ approval request ပို့နိုင်သည်;
  approve message တွင် IP/country/UA ပြပါ။
- **Warranty 48h grace** — full refund ပေးပြီး customer ထံ key/account ကျန်နေသည်; refund မတိုင်မီ key revoke/credential
  ပြောင်းရန် admin checklist ထည့်ပါ။
- **`adjust` ledger** (L16936) — `balance_after` ကို stale `u.balance+amt` ဖြင့် ရေးသည်; SELECT ပြန်ဖတ်ပါ။

---

## ဦးစားပေး ပြင်ဆင်ရန် အစီအစဉ်

1. Auto-Approve ကို ပိတ်ထား (သို့) #1 ၏ hold/trust-tier ထည့်ပါ — **ယနေ့**
2. #2 `Delivering` claim, #3 reverse atomic — code ပြောင်းလဲမှု သေးငယ်, risk မြင့်
3. #4 poison update attempt cap
4. #5 backup allowlist + `CREDENTIAL_SECRET` သတ်မှတ်ထားကြောင်း စစ်ပါ
5. #6–#9 accounting fixes
6. #8 receipt rate-limit
