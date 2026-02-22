"""
Unit tests for signal_engine/behavior.py (analyze_behavior).

Coverage:
- Empty / whitespace-only bodies → no signals, no excerpts
- Urgency patterns (account suspend, immediate action, 24-hour deadline,
  expire, verify identity, click-to-confirm)
- Credential solicitation patterns (enter password, banking details)
- Both patterns in one email → still one signal (10 pts — category cap)
- Excerpts list is populated on match, empty otherwise
- HTML body fallback when plain text is empty
- Plain text is preferred over HTML when both are present
- Safe/neutral email body → no signals
"""

from __future__ import annotations

import pytest

from signal_engine.behavior import analyze_behavior


class TestAnalyzeBehaviorEmptyInput:
    def test_both_empty_no_signals(self):
        signals, excerpts = analyze_behavior("", "")
        assert signals == []
        assert excerpts == []

    def test_whitespace_only_plain_text_no_signals(self):
        signals, excerpts = analyze_behavior("   \n\t  ", "")
        assert signals == []

    def test_whitespace_only_html_no_signals(self):
        signals, excerpts = analyze_behavior("", "   \n  ")
        assert signals == []


class TestAnalyzeBehaviorUrgencyPatterns:
    """Each test verifies a distinct urgency regex branch fires exactly once."""

    def test_account_will_be_suspended(self):
        signals, excerpts = analyze_behavior(
            "Your account will be suspended within 24 hours.", ""
        )
        assert len(signals) == 1
        assert signals[0].name == "Suspicious Body Content"
        assert signals[0].category == "behavior"
        assert signals[0].points == 10

    def test_account_closed_language(self):
        signals, _ = analyze_behavior(
            "Your account has been closed due to suspicious activity.", ""
        )
        assert len(signals) == 1

    def test_immediate_action_required(self):
        signals, _ = analyze_behavior(
            "Immediate action required to restore your access.", ""
        )
        assert len(signals) == 1

    def test_24_hour_deadline(self):
        signals, _ = analyze_behavior(
            "You have 24 hours to respond or lose access.", ""
        )
        assert len(signals) == 1

    def test_expires_soon(self):
        signals, _ = analyze_behavior(
            "Your subscription expires soon. Don't miss your last chance!", ""
        )
        assert len(signals) == 1

    def test_verify_your_identity(self):
        signals, _ = analyze_behavior(
            "Please verify your identity to continue.", ""
        )
        assert len(signals) == 1

    def test_click_here_to_confirm(self):
        signals, _ = analyze_behavior(
            "Click here to confirm your account details.", ""
        )
        assert len(signals) == 1

    def test_act_now_keyword(self):
        signals, _ = analyze_behavior(
            "Act now before it's too late!", ""
        )
        assert len(signals) == 1


class TestAnalyzeBehaviorCredentialPatterns:
    def test_enter_password_triggers_signal(self):
        signals, _ = analyze_behavior(
            "Please enter your password to verify your identity.", ""
        )
        assert len(signals) == 1
        assert signals[0].category == "behavior"

    def test_enter_credit_card_triggers_signal(self):
        signals, _ = analyze_behavior(
            "Please enter your credit card information below.", ""
        )
        assert len(signals) == 1

    def test_banking_details_triggers_signal(self):
        signals, _ = analyze_behavior(
            "Provide your banking details to process the refund.", ""
        )
        assert len(signals) == 1

    def test_confirm_payment_triggers_signal(self):
        signals, _ = analyze_behavior(
            "Confirm your payment and billing information.", ""
        )
        assert len(signals) == 1


class TestAnalyzeBehaviorOneSignalMaximum:
    def test_urgency_and_credential_produce_one_signal(self):
        """Both pattern types match → still only one Signal (behavior cap = 10 pts)."""
        text = (
            "Your account will be suspended in 24 hours. "
            "Enter your password to avoid suspension."
        )
        signals, excerpts = analyze_behavior(text, "")
        assert len(signals) == 1
        assert signals[0].points == 10

    def test_multiple_urgency_phrases_one_signal(self):
        text = (
            "Urgent! Immediate action required. "
            "Your account will be suspended within 24 hours!"
        )
        signals, _ = analyze_behavior(text, "")
        assert len(signals) == 1


class TestAnalyzeBehaviorExcerpts:
    def test_excerpts_populated_on_match(self):
        _, excerpts = analyze_behavior(
            "Your account will be suspended in 24 hours.", ""
        )
        assert len(excerpts) >= 1

    def test_excerpts_are_strings(self):
        _, excerpts = analyze_behavior(
            "Your account will be suspended in 24 hours.", ""
        )
        for ex in excerpts:
            assert isinstance(ex, str)

    def test_excerpts_empty_when_no_match(self):
        _, excerpts = analyze_behavior(
            "Thanks for your order. It will arrive by Friday.", ""
        )
        assert excerpts == []


class TestAnalyzeBehaviorHTMLFallback:
    def test_html_body_used_when_plain_empty(self):
        html = "<p>Your account will be <strong>suspended</strong> within 24 hours.</p>"
        signals, _ = analyze_behavior("", html)
        assert len(signals) == 1

    def test_plain_text_preferred_over_html(self):
        # plain text is safe, HTML has urgency — plain should win → no signal
        plain = "Thank you for your purchase. Have a great day!"
        html = "<p>Your account will be suspended in 24 hours.</p>"
        signals, _ = analyze_behavior(plain, html)
        assert signals == []

    def test_html_tags_stripped_before_matching(self):
        # Tags should not interfere with keyword matching
        html = "<div><b>Immediate</b> <em>action required</em> to unlock your account.</div>"
        signals, _ = analyze_behavior("", html)
        assert len(signals) == 1


class TestAnalyzeBehaviorSafeEmail:
    def test_order_confirmation_no_signals(self):
        signals, _ = analyze_behavior(
            "Thank you for your purchase. Your order #12345 will arrive by Friday.", ""
        )
        assert signals == []

    def test_meeting_invite_no_signals(self):
        signals, _ = analyze_behavior(
            "Hi team, let's meet tomorrow at 3pm to discuss the project roadmap.", ""
        )
        assert signals == []

    def test_newsletter_no_signals(self):
        signals, _ = analyze_behavior(
            "Check out our latest updates and product announcements for February 2026.", ""
        )
        assert signals == []
