"""Hand-written smoke corpus: 20 known phishing emails and 20 legitimate ones.

These are deliberately synthetic but archetypal emails with no real personal
data. Ordinary sender and link hosts use reserved example ranges
(example/example.com/example.org and the documentation IP blocks); the
lookalike artifacts under test (punycode hosts, homoglyph brand domains)
are crafted fixture text and never resolve anywhere this corpus is used.

`CREDENTIAL_PHISH_EXEMPLAR` is the Phase 1 acceptance anchor: the classic
credential-theft phish (brand display name, lookalike sender domain, link
to that same lookalike domain asking for the password) on which
`asks_credentials` must dominate.
"""

CREDENTIAL_PHISH_EXEMPLAR = """\
From: "PayPal Security" <no-reply@paypal-account-verify.example>
To: customer@corp.example
Subject: URGENT: Your account has been limited - action required within 24 hours
Date: Tue, 2 Jun 2026 09:14:00 +0000
Message-ID: <limited-8821@paypal-account-verify.example>
Content-Type: text/plain; charset="utf-8"

Dear Customer,

We detected unusual activity on your account and have temporarily limited
it. To restore full access you must confirm your password within 24 hours.

Please confirm your account login through the link below:

https://paypal-account-verify.example/webscr/cmd=account-verification

If you do not confirm your login in time, your account will be permanently
closed.

Thank you for your cooperation.
PayPal Security Team
"""

PHISHING_EMAILS = [
    CREDENTIAL_PHISH_EXEMPLAR,
    # Microsoft 365 credential phish with punycode host.
    """\
From: "Microsoft 365 Team" <security@m365-login-alerts.example>
To: employee@corp.example
Subject: Action required: your mailbox will be deactivated
Date: Tue, 2 Jun 2026 08:02:00 +0000
Content-Type: text/plain; charset="utf-8"

Your Microsoft 365 mailbox could not be re-authenticated. Sign in at
https://xn--microsoft-2ve.com/owa/auth to validate your password before
9:00 AM tomorrow or mailbox access will be suspended.

Microsoft Account Team
""",
    # Bank credential phish with exact homoglyph sender domain (Cyrillic а).
    """\
From: "Wells Fargo Online" <alerts@wellsfаrgo.com>
To: victim@corp.example
Subject: Security alert: confirm your online banking password
Date: Tue, 2 Jun 2026 10:31:00 +0000
Content-Type: text/plain; charset="utf-8"

We locked your online banking profile after three failed sign-in attempts.
Unlock it by confirming your password and SSN at
https://wellsfargo-verify.example/unlock within 12 hours.

Online Banking Team
""",
    # Invoice phish leading to a credential page.
    """\
From: "Accounts Payable" <invoices@docusign-billing.example>
To: finance@corp.example
Subject: Overdue invoice #INV-77419 - payment required
Date: Wed, 3 Jun 2026 11:05:00 +0000
Content-Type: text/plain; charset="utf-8"

The attached invoice INV-77419 for $2,847.00 is 14 days overdue.
Review the invoice and approve the payment by signing in with your email
account password at http://198.51.100.7/docusign/invoice-approval.

Accounts Payable Automation
""",
    # Gift-card CEO fraud.
    """\
From: "Margaret Hale" <m.hale@ce0-office.example>
To: assistant@corp.example
Subject: Quick task
Date: Wed, 3 Jun 2026 07:45:00 +0000
Content-Type: text/plain; charset="utf-8"

I'm in a board meeting and can't take calls. I need you to buy 8 x $100
Apple gift cards right now for client thank-yous and reply with the
scratch-off codes. Keep this between us for now.

Margaret
CEO Office
""",
    # Wire-transfer fraud with secrecy pressure.
    """\
From: "David Tennant" <d.tennant@cfo-office.example>
To: payments@corp.example
Subject: Confidential: supplier bank change
Date: Thu, 4 Jun 2026 16:20:00 +0000
Content-Type: text/plain; charset="utf-8"

Do not discuss this with anyone in accounting yet. Our supplier Jakob
Logistics changed their bank. Route today's outstanding transfer of
EUR 41,300 to the new IBAN below and confirm by replying only to me.

IBAN: LT00 0000 0000 0000 0000

David
""",
    # Lottery scam.
    """\
From: "International Lottery Commission" <claims@lottery-intl.example>
To: winner@corp.example
Subject: CONGRATULATIONS!!! You have won GBP 2,500,000.00
Date: Thu, 4 Jun 2026 12:00:00 +0000
Content-Type: text/plain; charset="utf-8"

Your email address was selected at random in our international lottery.
You have won GBP 2,500,000.00. To begin the claim of your winnings, send
your full name, date of birth and phone number to our claims agent within
7 days.

Claims Department
""",
    # Inheritance / advance-fee scam.
    """\
From: "Barrister Uche Kalu" <barrister.uche@law-chambers.example>
To: recipient@corp.example
Subject: STRICTLY CONFIDENTIAL BUSINESS PROPOSAL
Date: Fri, 5 Jun 2026 06:30:00 +0000
Content-Type: text/plain; charset="utf-8"

I represent the estate of a late client with an unclaimed fund of
USD 8,200,000. With your consent I will present you as the next of kin
and we split the funds 60/40. Keep this absolutely confidential. First
I need a copy of your passport and a USD 850 processing fee.

Barrister Uche Kalu (Esq.)
""",
    # Crypto giveaway scam.
    """\
From: "Coinbase Promotions" <promo@coinbase-rewards.example>
To: trader@corp.example
Subject: 500 ETH giveaway - send 1 ETH, receive 500 back
Date: Fri, 5 Jun 2026 18:11:00 +0000
Content-Type: text/plain; charset="utf-8"

To celebrate our listing we are giving away 5,000 ETH. Send 1-10 ETH to
the address below and receive 5x back within 10 minutes. Event ends at
midnight tonight.

0x000000000000000000000000000000000000dEaD
""",
    # Delivery-fee bait with PII collection.
    """\
From: "DHL Express" <parcel-notice@dhl-parcel-track.example>
To: shopper@corp.example
Subject: Your parcel is held - delivery fee unpaid
Date: Sat, 6 Jun 2026 09:00:00 +0000
Content-Type: text/plain; charset="utf-8"

Parcel #DHL-9912456 from abroad is on hold: customs fee of $1.99 unpaid.
Pay the fee and complete delivery by confirming your full name, address
and card number at https://dhl-fee-pay.example/track within 48 hours or
the parcel returns to sender.

DHL Express Notifications
""",
    # Netflix payment-card phish.
    """\
From: "Netflix" <billing@netflix-payment-update.example>
To: viewer@corp.example
Subject: Your payment was declined - update payment method
Date: Sat, 6 Jun 2026 20:44:00 +0000
Content-Type: text/plain; charset="utf-8"

We could not process your last payment. Your account will be suspended
in 24 hours. Update your card number, expiry and CVV at
http://192.0.2.88/netflix/payment to keep watching.

Netflix Billing
""",
    # Apple ID credential phish with reply-to mismatch.
    """\
From: "Apple Support" <no-reply@appleid-verify.example>
Reply-To: appleid.help@mail.example.org
To: user@corp.example
Subject: Your Apple ID has been locked for security reasons
Date: Sun, 7 Jun 2026 11:22:00 +0000
Content-Type: text/plain; charset="utf-8"

Too many incorrect password attempts were made on your Apple ID. Confirm
your Apple ID password at https://appleid-locked.example/verify now. If
you do not, the account will be deleted in 3 days.

Apple Support
""",
    # Amazon order-phish with brand-in-subdomain host.
    """\
From: "Amazon.com" <orders@amazon-order-update.example>
To: shopper@corp.example
Subject: Problem with order #402-7715398-2219
Authentication-Results: mx.corp.example; spf=fail (sender IP is 203.0.113.77) smtp.mailfrom=amazon-order-update.example; dkim=fail
Date: Sun, 7 Jun 2026 15:03:00 +0000
Content-Type: text/plain; charset="utf-8"

Your payment method was declined for order #402-7715398-2219. The order
is on hold. Sign in with your Amazon password at
https://amazon.com.order-resolve.example/signin within 2 days to approve
an alternative card, or the order will be cancelled.

Amazon.com Customer Service
""",
    # Unclaimed-refund bait with callback pressure.
    """\
From: "IRS Tax Refund" <refund@irs-refund-portal.example>
To: taxpayer@corp.example
Subject: Unclaimed tax refund of $4,917.28 expires this week
Date: Mon, 8 Jun 2026 08:59:00 +0000
Content-Type: text/plain; charset="utf-8"

Our records show an unclaimed tax refund of $4,917.28 in your name. The
claim window closes Friday. Submit your social security number and filing
status at https://irs-refund-claim.example/submit to release the payment.

Refund Processing Department
""",
    # Sextortion-adjacent account-threat scam (no explicit content).
    """\
From: "Security Alert" <system@mailbox-quota.example>
To: user@corp.example
Subject: Final warning: mailbox will be deleted in 6 hours
Date: Mon, 8 Jun 2026 03:12:00 +0000
Content-Type: text/plain; charset="utf-8"

Your mailbox exceeded its storage quota. All incoming mail is being
rejected. Click http://203.0.113.250/quota/upgrade and confirm your
account password within 6 hours or the mailbox and all messages will be
permanently deleted.

Mail System Administrator
""",
    # HR-benefits credential phish (internal-looking).
    """\
From: "Human Resources" <hr-benefits@corp-portal-login.example>
To: staff@corp.example
Subject: Benefits enrollment closes TODAY - password required
Date: Tue, 9 Jun 2026 07:02:00 +0000
Content-Type: text/plain; charset="utf-8"

Open enrollment for 2027 benefits closes at 6 PM today. Late enrollment
is impossible and default coverage will be reduced. Log in with your
corporate email password at http://benefits-enroll.example/login to
confirm your elections immediately.

HR Benefits Team
""",
    # Tech-support scare scam.
    """\
From: "Microsoft Security" <alert@defender-warning.example>
To: user@corp.example
Subject: 34 viruses detected on your computer
Date: Tue, 9 Jun 2026 14:40:00 +0000
Content-Type: text/plain; charset="utf-8"

Windows Defender detected 34 viruses and trojans on your computer. Your
files are at immediate risk of deletion. Call our support hotline within
30 minutes or run the removal tool at
http://198.51.100.99/defender/clean.exe to enter your license password.

Microsoft Security Alert
""",
    # Fake job offer with check-cash request.
    """\
From: "Recruitment" <hiring@global-mystery-shoppers.example>
To: jobseeker@corp.example
Subject: You are hired: mystery shopper position, $400/task
Date: Wed, 10 Jun 2026 10:10:00 +0000
Content-Type: text/plain; charset="utf-8"

Congratulations! You are selected as a mystery shopper earning $400 per
task. Your first assignment: deposit the $2,900 check we mail you, keep
$400, and wire the rest to our evaluator to test the wire service. Reply
with your full name, address and bank name to receive the check package
today.

Recruitment Desk
""",
    # Social-media verification phish.
    """\
From: "Instagram Support" <verify@instagram-badge-center.example>
To: creator@corp.example
Subject: Apply for the verified badge before the deadline
Date: Wed, 10 Jun 2026 17:55:00 +0000
Content-Type: text/plain; charset="utf-8"

Your account is pre-approved for the verified badge. Verify your login
credentials at https://instagram-badge.example/verify by tomorrow or the
approval expires and your account may be flagged for impersonation.

Instagram Support Team
""",
    # Voicemail-bait with credential link.
    """\
From: "Corp Voicemail" <voicemail@corp-telephony-secure.example>
To: staff@corp.example
Subject: You have (1) new voicemail from Unknown Caller
Date: Thu, 11 Jun 2026 09:33:00 +0000
Content-Type: text/plain; charset="utf-8"

You have 1 new voicemail message (42 seconds) held for 24 hours. To
listen, authenticate with your directory password at
http://203.0.113.14/voicemail/login?u=staff.

Telephony System
""",
]

LEGIT_EMAILS = [
    # Plain internal release notes.
    """\
From: Alice Nguyen <alice.nguyen@acme-corp.example>
To: eng-team@acme-corp.example
Subject: Release notes 1.4.2
Date: Mon, 1 Jun 2026 16:00:00 +0000
Content-Type: text/plain; charset="utf-8"

Hi all,

Release 1.4.2 is out. Highlights: faster sync, two crash fixes, updated
docs. See the changelog for details.

Best,
Alice
""",
    # Meeting invitation.
    """\
From: "Priya Raman" <priya.raman@acme-corp.example>
To: alice.nguyen@acme-corp.example
Subject: Q3 planning - Thursday 10:00
Date: Tue, 2 Jun 2026 11:30:00 +0000
Content-Type: text/plain; charset="utf-8"

Hi Alice,

Moving our Q3 planning session to Thursday at 10:00 in Room 4B. Agenda
attached to the calendar invite. Bring your team's roadmap slide.

Thanks,
Priya
""",
    # Order confirmation from a real merchant.
    """\
From: orders@books.example.com
To: shopper@corp.example
Subject: Your order #B-55821 has shipped
Date: Tue, 2 Jun 2026 13:07:00 +0000
Content-Type: text/plain; charset="utf-8"

Thanks for your order. "The Pragmatic Programmer" (paperback, $34.99)
shipped today via standard post and should arrive June 9. Track it with
tracking code 1Z999AA10123456784 on the carrier's site.

Books Example Customer Service
""",
    # Requested password reset (hard legit case: mentions credentials).
    """\
From: GitHub <noreply@github.example>
To: developer@corp.example
Subject: [GitHub] Reset your password - request from Chrome on Windows
Authentication-Results: mx.corp.example; spf=pass smtp.mailfrom=github.example; dkim=pass
Date: Tue, 2 Jun 2026 18:22:00 +0000
Content-Type: text/plain; charset="utf-8"

We received a request to reset your GitHub password. Open
https://github.example/password_reset/token/5Xy8zQ to choose a new one.
This link expires in 30 minutes. If you did not request this, ignore
this email and your password stays unchanged.

GitHub Support
""",
    # Calendar reminder with genuine deadline (no threat).
    """\
From: calendar@acme-corp.example
To: team-leads@acme-corp.example
Subject: Reminder: expense reports due Friday
Date: Wed, 3 Jun 2026 08:00:00 +0000
Content-Type: text/plain; charset="utf-8"

Friendly reminder: May expense reports are due to Finance by Friday
17:00. Submit through the usual finance portal as in previous months.

Calendar Assistant
""",
    # Newsletter the recipient reads.
    """\
From: "Python Weekly" <news@pythonweekly.example>
To: developer@corp.example
Subject: Python Weekly: Issue 529
Date: Wed, 3 Jun 2026 12:00:00 +0000
Content-Type: text/plain; charset="utf-8"

This week: a deep dive on the new pattern-matching ergonomics, a
benchmark of async web frameworks, and three libraries worth a look.
Read the full issue at https://pythonweekly.example/issue/529.

You receive this because you subscribed. Unsubscribe anytime.
""",
    # Internal code review request.
    """\
From: "Marcus Reid" <marcus.reid@acme-corp.example>
To: alice.nguyen@acme-corp.example
Subject: Review request: PR #812 (sync retry logic)
Date: Wed, 3 Jun 2026 15:41:00 +0000
Content-Type: text/plain; charset="utf-8"

Alice,

Could you review PR #812 when you get a chance? It adds exponential
backoff to the sync client. No rush - by end of week is fine.

Marcus
""",
    # Bank statement notice (no credentials requested).
    """\
From: statements@firstcommunitybank.example
To: account-holder@corp.example
Subject: Your May statement is available
Authentication-Results: mx.corp.example; spf=pass (sender IP is 198.51.100.10) smtp.mailfrom=firstcommunitybank.example; dkim=pass
Date: Thu, 4 Jun 2026 06:05:00 +0000
Content-Type: text/plain; charset="utf-8"

Your May 2026 account statement is ready. View it any time by signing
in to online banking from our website at https://www.firstcommunitybank.example.

First Community Bank
""",
    # Support ticket update.
    """\
From: helpdesk@saas-vendor.example
To: ops@corp.example
Subject: [Ticket #44172] Re: Latency spikes on EU cluster - resolved
Date: Thu, 4 Jun 2026 09:26:00 +0000
Content-Type: text/plain; charset="utf-8"

Hi,

The latency spikes on your EU cluster were caused by a misconfigured
load balancer; we rotated it at 08:50 UTC and metrics look normal. Can
you confirm things look good on your side? We'll keep the ticket open
until you reply.

SaaS Vendor Support
""",
    # Conference talk acceptance.
    """\
From: "PyCon Program Committee" <program@pycon.example>
To: speaker@corp.example
Subject: Your talk "Small models, sharp questions" was accepted
Date: Thu, 4 Jun 2026 14:12:00 +0000
Content-Type: text/plain; charset="utf-8"

Congratulations - your 25-minute talk was accepted for the main track.
Please confirm your attendance by June 20 through the speaker portal
(link in your speaker account).

PyCon Program Committee
""",
    # Delivery notification from a real carrier (no fee).
    """\
From: "UPS" <no-reply@ups.example>
To: shopper@corp.example
Subject: UPS: delivery scheduled for tomorrow between 9:00-13:00
Date: Fri, 5 Jun 2026 07:55:00 +0000
Content-Type: text/plain; charset="utf-8"

Your shipment 1Z999AA10123456784 from Books Example is scheduled for
delivery tomorrow between 9:00 and 13:00. No signature is required.

UPS On-Route Notifications
""",
    # Internal security awareness note (mentions phishing, teaches).
    """\
From: "IT Security" <security@acme-corp.example>
To: all-staff@acme-corp.example
Subject: This quarter's phishing drill results
Date: Fri, 5 Jun 2026 11:47:00 +0000
Content-Type: text/plain; charset="utf-8"

Team,

Last week's drill: 12% clicked the simulated credential phish, down from
19%. Great progress. Remember: we never ask for your password by email.
Report suspicious mail with the "Report phishing" button.

IT Security
""",
    # PTO request to a manager.
    """\
From: "Jonas Weber" <jonas.weber@acme-corp.example>
To: priya.raman@acme-corp.example
Subject: PTO request: June 22-26
Date: Fri, 5 Jun 2026 16:20:00 +0000
Content-Type: text/plain; charset="utf-8"

Hi Priya,

I'd like to take June 22-26 off. The handover doc for the pipeline work
is ready and Alex agreed to cover on-call. OK to approve in the HR
system?

Jonas
""",
    # Receipt for a purchase already made.
    """\
From: receipts@coffee.example
To: shopper@corp.example
Subject: Your receipt from The Daily Grind - $6.40
Date: Sat, 6 Jun 2026 09:12:00 +0000
Content-Type: text/plain; charset="utf-8"

Thanks for your purchase.

The Daily Grind, 12 Market St
1x flat white        $4.20
1x almond croissant  $2.20
Total                $6.40 (card ending 4417)

A tip of 15% was added as selected on the terminal.
""",
    # Community event announcement.
    """\
From: "Berlin Rust Meetup" <organizers@rustberlin.example>
To: developer@corp.example
Subject: Next Tuesday: "Zero-cost abstractions in parsers"
Date: Sat, 6 Jun 2026 12:30:00 +0000
Content-Type: text/plain; charset="utf-8"

Hi all,

Next Tuesday Anna K. walks us through building a streaming parser with
zero-cost abstractions. Doors at 18:30, talk at 19:00, followed by the
usual social. RSVP on the meetup page if you're coming.

See you there,
Organizers
""",
    # Vendor renewal notice (money, but through normal channel).
    """\
From: billing@cloudhost.example
To: finance@corp.example
Subject: Your cloudhost plan renews on July 1
Date: Sun, 7 Jun 2026 10:00:00 +0000
Content-Type: text/plain; charset="utf-8"

Your Pro plan ($149/month, card ending 0229) renews automatically on
July 1 as part of your standard agreement - no action needed. Invoices
appear in your billing portal after each renewal.

cloudhost Billing
""",
    # Family/personal email.
    """\
From: "Rosa Delgado" <rosa.delgado@freemail.example>
To: family@corp.example
Subject: Sunday lunch at 1?
Date: Sun, 7 Jun 2026 12:15:00 +0000
Content-Type: text/plain; charset="utf-8"

Hola! Sunday lunch at our place at 1? I'm making the paella and Dani is
bringing dessert. Let me know if you can make it.

Un abrazo,
Rosa
""",
    # HR policy update (internal, informational).
    """\
From: "People Operations" <people-ops@acme-corp.example>
To: all-staff@acme-corp.example
Subject: Updated remote-work policy (effective next quarter)
Date: Mon, 8 Jun 2026 09:00:00 +0000
Content-Type: text/plain; charset="utf-8"

Hello,

The updated remote-work policy is attached to the intranet policy page.
Summary: up to 3 remote days per week by default, team charters may add
guidelines. Questions to people-ops@acme-corp.example - no reply needed.

People Operations
""",
    # Documentation contribution thank-you.
    """\
From: "OpenDocs Editors" <editors@opendocs.example>
To: contributor@corp.example
Subject: Your guide was merged - thank you!
Date: Mon, 8 Jun 2026 17:31:00 +0000
Content-Type: text/plain; charset="utf-8"

Hi,

Your "Getting started with the CLI" guide was reviewed and merged into
the docs site today. Two copy-edits were applied. Thank you for the
contribution!

OpenDocs Editors
""",
    # Scheduled maintenance window (downtime, but routine and no demand).
    """\
From: "IT Operations" <itops@acme-corp.example>
To: all-staff@acme-corp.example
Subject: Scheduled maintenance: wiki read-only Saturday 22:00-02:00
Date: Tue, 9 Jun 2026 08:15:00 +0000
Content-Type: text/plain; charset="utf-8"

Hello,

The internal wiki will be read-only this Saturday from 22:00 to 02:00
UTC while we upgrade the storage backend. No action needed; edits made
before the window are safe.

IT Operations
""",
]

assert len(PHISHING_EMAILS) == 20, "smoke corpus must hold 20 phishing emails"
assert len(LEGIT_EMAILS) == 20, "smoke corpus must hold 20 legitimate emails"
