---
name: gmail-addon-ui-ux
description: Use this skill when building, designing, or refining Gmail Add-on interfaces. Triggered by requests involving Gmail cards, sidebars, compose actions, contextual widgets, CardService UI, or any Google Workspace Add-on frontend.
compatibility: frontend-designer
user-invokable: true
---

# Gmail Add-on UI/UX Skill

This skill governs the design and implementation of Gmail Add-ons using Google's
CardService API. It pairs with the `frontend-designer` skill: use that skill for
aesthetic direction, color, typography, and motion philosophy — use THIS skill for
Gmail-specific constraints, patterns, and component architecture.

---

## Gmail Add-on Fundamentals

Gmail Add-ons render inside a constrained card-based UI via **CardService** (Apps Script)
or **Google Workspace Add-ons API** (JSON manifest + endpoints). You do NOT write raw HTML —
you compose UI from Google's card primitives.

### Core Building Blocks

| Component | Use For |
|---|---|
| `CardService.newCard()` | Top-level screen/view |
| `CardSection` | Grouping related widgets |
| `TextInput` | User text entry |
| `SelectionInput` | Dropdowns, checkboxes, radio |
| `ButtonSet` / `TextButton` | Actions and CTAs |
| `DecoratedText` | Label + value rows with icons |
| `Image` | Inline images |
| `Divider` | Visual separation |
| `FixedFooter` | Sticky bottom action bar |
| `Navigation` | Push/pop card stack |

---

## Design Principles for Gmail Add-ons

### 1. Respect the Container
Gmail's sidebar is **~300px wide**. Design for a narrow, vertical, scrollable column.
- Never assume horizontal space
- Stack elements vertically
- Use `DecoratedText` for dense information display
- Avoid overwhelming the user — Gmail is already information-dense

### 2. Card Stack = Navigation
Gmail Add-ons use a card stack instead of pages:
```javascript
// Push to a new "page"
CardService.newNavigation().pushCard(detailCard)

// Go back
CardService.newNavigation().popCard()

// Replace entire stack
CardService.newNavigation().updateCard(newCard)
```
Design each card as a **focused, single-purpose screen**. No card should try to do everything.

### 3. Contextual Awareness
Great Gmail Add-ons react to the email being read:
```javascript
function onGmailMessage(e) {
  const messageId = e.gmail.messageId;
  const accessToken = e.gmail.accessToken;
  GmailApp.setCurrentMessageAccessToken(accessToken);
  const message = GmailApp.getMessageById(messageId);
  const subject = message.getSubject();
  const sender = message.getFrom();
  // Now personalize your card based on context
}
```
Always read available context (`messageId`, `threadId`, `userEmail`) and surface relevant info immediately — don't make users re-enter what Gmail already knows.

### 4. Loading & Async UX
CardService is synchronous — every action triggers a server round-trip. Design for this:
- Use clear, action-oriented button labels ("Analyze Email", "Save to CRM")
- Show confirmation cards after actions complete
- Use `CardService.newNotification()` for lightweight feedback toasts
- Design "success" and "error" cards as distinct states

---

## UX Patterns

### Pattern 1: Home Card (Default View)
The first card a user sees. Should:
- Immediately show value relevant to the current email
- Have a clear primary action in a `FixedFooter`
- Use `DecoratedText` rows for at-a-glance info
- Be scannable in under 3 seconds

```javascript
function buildHomeCard(subject, sender) {
  return CardService.newCardBuilder()
    .setHeader(CardService.newCardHeader()
      .setTitle('YourApp')
      .setSubtitle('Email Intelligence')
      .setImageUrl('https://yourdomain.com/logo.png'))
    .addSection(CardService.newCardSection()
      .setHeader('Current Email')
      .addWidget(CardService.newDecoratedText()
        .setTopLabel('From')
        .setText(sender))
      .addWidget(CardService.newDecoratedText()
        .setTopLabel('Subject')
        .setText(subject)))
    .setFixedFooter(CardService.newFixedFooter()
      .setPrimaryButton(CardService.newTextButton()
        .setText('Analyze')
        .setOnClickAction(CardService.newAction()
          .setFunctionName('onAnalyze'))))
    .build();
}
```

### Pattern 2: Form Card
For data entry. Rules:
- One logical task per form
- Label every field clearly (use `setTitle` + `setHint`)
- Always include a Back button + Submit in `FixedFooter`
- Validate server-side and return error cards on failure

### Pattern 3: Detail / Result Card
Shown after an action completes. Should:
- Confirm what happened ("✓ Saved to CRM")
- Show the result data cleanly
- Offer a logical next action
- Have a Back button to return to home

### Pattern 4: Settings Card
Accessible from a header overflow menu. Keep separate from core workflow.

---

## Working with the Frontend Designer Skill

The `frontend-designer` skill defines your **visual identity** — apply it here through:

| Frontend Designer Concept | Gmail Add-on Application |
|---|---|
| Color palette | Card header background color, button colors |
| Typography personality | Card header title wording/tone, label text style |
| Minimalist vs maximalist | Sparse sections vs information-dense `DecoratedText` lists |
| Motion philosophy | Use `Notification` toasts instead of full card swaps for minor feedback |
| Brand voice | Button labels, section headers, helper hint text |

Since CardService limits raw CSS, express the frontend-designer aesthetic through:
- **Header images/icons** that match brand identity
- **Consistent iconography** using Material Icons (built into CardService)
- **Section headers** that use the brand's tone of voice
- **Color choices** in `TextButton.setTextButtonStyle()` and header backgrounds

---

## Manifest Setup (`appsscript.json`)

```json
{
  "timeZone": "America/New_York",
  "dependencies": {},
  "exceptionLogging": "STACKDRIVER",
  "runtimeVersion": "V8",
  "gmail": {
    "name": "Your Add-on Name",
    "logoUrl": "https://yourdomain.com/logo.png",
    "primaryColor": "#1A1A2E",
    "secondaryColor": "#E94560",
    "authorizationCheckFunction": "onAuthorizationRequired",
    "contextualTriggers": [{
      "unconditional": {},
      "onTriggerFunction": "onGmailMessage"
    }],
    "composeTrigger": {
      "selectActions": [{
        "text": "Open Your Add-on",
        "runFunction": "onComposeOpen"
      }],
      "draftAccess": "METADATA"
    }
  }
}
```

---

## Quality Checklist

Before shipping any Gmail Add-on UI, verify:

- [ ] Home card loads in under 2 seconds
- [ ] Every button has a clear, specific label (no "Submit" or "OK")
- [ ] All cards have a logical back/exit path
- [ ] Error states are designed (not just happy path)
- [ ] Empty states are designed (first-time user, no data)
- [ ] Tested in both Gmail web and mobile
- [ ] Card header has logo/icon for brand recognition
- [ ] No card tries to do more than one thing
- [ ] `FixedFooter` used for primary CTA on all action cards
- [ ] Contextual data from the email is surfaced immediately

---

## Anti-Patterns to Avoid

- **Wall of text** — Use `DecoratedText` rows instead of long `TextParagraph` blocks
- **Too many sections** — Aim for 1–3 sections per card; split into sub-cards if needed
- **Generic labels** — "Button 1" or "Submit" tells the user nothing
- **Ignoring mobile** — Gmail Add-ons run on Android/iOS; test on small screens
- **Blocking the compose window** — Compose add-ons should be lightweight and fast
- **Reinventing navigation** — Use the card stack; don't simulate routing with hidden widgets