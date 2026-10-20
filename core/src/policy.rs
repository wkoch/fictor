//! Pure Phase-0 policy precedence from spec/05-security.md#decisão.
//!
//! Inputs come from trusted core state: approved classification, current
//! session state, exact-name grants and configuration decisions. The caller
//! supplies `matching_rules` after matching the exposed name. Glob syntax is
//! awaiting ARQ-032. An Allow result alone does not execute or audit a call.

pub mod provenance;

use crate::{
    config::{Decision as RuleDecision, Mode},
    installer::manifest::{Effect, Sensitivity},
    store::Flags,
};

#[derive(Clone, Copy, Debug)]
pub struct Tool<'a> {
    pub name: &'a str,
    pub enabled: bool,
    pub effect: Effect,
    pub sensitivity: Sensitivity,
}

#[derive(Clone, Copy, Debug)]
pub struct Session<'a> {
    pub mode: Mode,
    pub flags: Flags,
    pub kind: &'a str,
}

/// Grants match complete exposed names case sensitively. A grant containing
/// `*` is a literal name, not a pattern authorizing other tools.
#[derive(Clone, Copy, Debug, Default)]
pub struct Grants<'a> {
    pub session: &'a [String],
    pub permanent: &'a [String],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllowReason {
    Grant,
    Config,
    DefaultMode,
    AutoMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DenyReason {
    ToolUnavailable,
    Config,
    PlanMode,
    EvalWithoutHuman,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AskReason {
    RuleOfTwo,
    Config,
    DefaultMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApprovalScopes {
    OnceOnly,
    OnceSessionAlways,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow(AllowReason),
    Deny(DenyReason),
    Ask {
        reason: AskReason,
        scopes: ApprovalScopes,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("the specification does not define the plan-mode read fallback")]
    UndefinedPlanRead,
}

/// Decide without persistence, execution or changing flags/grants. Eval
/// sessions turn every Ask into Deny. Rule-of-Two requests are always once-only.
pub fn decide(
    tool: Option<&Tool<'_>>,
    session: &Session<'_>,
    grants: Grants<'_>,
    matching_rules: &[RuleDecision],
) -> Result<Decision, PolicyError> {
    let decision = decide_normal(tool, session, grants, matching_rules)?;
    if session.kind == "eval" && matches!(decision, Decision::Ask { .. }) {
        Ok(Decision::Deny(DenyReason::EvalWithoutHuman))
    } else {
        Ok(decision)
    }
}

fn decide_normal(
    tool: Option<&Tool<'_>>,
    session: &Session<'_>,
    grants: Grants<'_>,
    matching_rules: &[RuleDecision],
) -> Result<Decision, PolicyError> {
    let Some(tool) = tool.filter(|tool| tool.enabled) else {
        return Ok(Decision::Deny(DenyReason::ToolUnavailable));
    };
    if matching_rules
        .iter()
        .any(|rule| matches!(rule, RuleDecision::Deny))
    {
        return Ok(Decision::Deny(DenyReason::Config));
    }
    if session.mode == Mode::Plan && tool.effect != Effect::Read {
        return Ok(Decision::Deny(DenyReason::PlanMode));
    }
    if tool.effect == Effect::External
        && session.flags.untrusted
        && (session.flags.private || tool.sensitivity == Sensitivity::Private)
    {
        return Ok(Decision::Ask {
            reason: AskReason::RuleOfTwo,
            scopes: ApprovalScopes::OnceOnly,
        });
    }
    if grants
        .session
        .iter()
        .chain(grants.permanent)
        .any(|name| name == tool.name)
    {
        return Ok(Decision::Allow(AllowReason::Grant));
    }
    if matching_rules
        .iter()
        .any(|rule| matches!(rule, RuleDecision::Ask))
    {
        return Ok(Decision::Ask {
            reason: AskReason::Config,
            scopes: ApprovalScopes::OnceSessionAlways,
        });
    }
    if matching_rules
        .iter()
        .any(|rule| matches!(rule, RuleDecision::Allow))
    {
        return Ok(Decision::Allow(AllowReason::Config));
    }
    match session.mode {
        Mode::Plan => Err(PolicyError::UndefinedPlanRead),
        Mode::Auto => Ok(Decision::Allow(AllowReason::AutoMode)),
        Mode::Default => Ok(match tool.effect {
            Effect::Read | Effect::WriteLocal => Decision::Allow(AllowReason::DefaultMode),
            Effect::External => Decision::Ask {
                reason: AskReason::DefaultMode,
                scopes: ApprovalScopes::OnceSessionAlways,
            },
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NAME: &str = "fs-tools__read_file";

    fn tool(effect: Effect, sensitivity: Sensitivity) -> Tool<'static> {
        Tool {
            name: NAME,
            enabled: true,
            effect,
            sensitivity,
        }
    }

    fn session(mode: Mode, untrusted: bool, private: bool) -> Session<'static> {
        Session {
            mode,
            flags: Flags { untrusted, private },
            kind: "interactive",
        }
    }

    fn ask(reason: AskReason, scopes: ApprovalScopes) -> Decision {
        Decision::Ask { reason, scopes }
    }

    #[test]
    fn missing_or_disabled_tool_precedes_every_other_rule() {
        let session = session(Mode::Auto, true, true);
        let names = [NAME.into()];
        let grants = Grants {
            session: &names,
            permanent: &names,
        };
        let rules = [RuleDecision::Allow, RuleDecision::Ask, RuleDecision::Deny];
        assert_eq!(
            decide(None, &session, grants, &rules),
            Ok(Decision::Deny(DenyReason::ToolUnavailable))
        );
        let disabled = Tool {
            enabled: false,
            ..tool(Effect::External, Sensitivity::Private)
        };
        assert_eq!(
            decide(Some(&disabled), &session, grants, &rules),
            Ok(Decision::Deny(DenyReason::ToolUnavailable))
        );
    }

    #[test]
    fn deny_is_highest_for_available_tools_independent_of_rule_order() {
        let names = [NAME.into()];
        let grants = Grants {
            session: &names,
            permanent: &names,
        };
        for mode in [Mode::Plan, Mode::Default, Mode::Auto] {
            for effect in [Effect::Read, Effect::WriteLocal, Effect::External] {
                for rules in [
                    [RuleDecision::Deny, RuleDecision::Ask, RuleDecision::Allow],
                    [RuleDecision::Ask, RuleDecision::Allow, RuleDecision::Deny],
                    [RuleDecision::Allow, RuleDecision::Deny, RuleDecision::Ask],
                ] {
                    assert_eq!(
                        decide(
                            Some(&tool(effect, Sensitivity::Private)),
                            &session(mode, true, true),
                            grants,
                            &rules
                        ),
                        Ok(Decision::Deny(DenyReason::Config))
                    );
                }
            }
        }
    }

    #[test]
    fn plan_blocks_writes_and_external_effects_before_grants_or_rule_of_two() {
        let names = [NAME.into()];
        let grants = Grants {
            session: &names,
            permanent: &names,
        };
        for effect in [Effect::WriteLocal, Effect::External] {
            for untrusted in [false, true] {
                assert_eq!(
                    decide(
                        Some(&tool(effect, Sensitivity::Private)),
                        &session(Mode::Plan, untrusted, true),
                        grants,
                        &[RuleDecision::Allow]
                    ),
                    Ok(Decision::Deny(DenyReason::PlanMode))
                );
            }
        }
    }

    #[test]
    fn undefined_plan_read_fallback_never_invents_a_product_decision() {
        let session = session(Mode::Plan, true, true);
        let tool = tool(Effect::Read, Sensitivity::Private);
        assert_eq!(
            decide(Some(&tool), &session, Grants::default(), &[]),
            Err(PolicyError::UndefinedPlanRead)
        );
        let names = [NAME.into()];
        assert_eq!(
            decide(
                Some(&tool),
                &session,
                Grants {
                    session: &names,
                    permanent: &[]
                },
                &[]
            ),
            Ok(Decision::Allow(AllowReason::Grant))
        );
        assert_eq!(
            decide(
                Some(&tool),
                &session,
                Grants::default(),
                &[RuleDecision::Ask]
            ),
            Ok(ask(AskReason::Config, ApprovalScopes::OnceSessionAlways))
        );
        assert_eq!(
            decide(
                Some(&tool),
                &session,
                Grants::default(),
                &[RuleDecision::Allow]
            ),
            Ok(Decision::Allow(AllowReason::Config))
        );
    }

    #[test]
    fn rule_of_two_matrix_cannot_be_bypassed_by_grants_auto_or_allow() {
        let names = [NAME.into()];
        for mode in [Mode::Default, Mode::Auto] {
            for effect in [Effect::Read, Effect::WriteLocal, Effect::External] {
                for sensitivity in [Sensitivity::Public, Sensitivity::Private] {
                    for untrusted in [false, true] {
                        for private in [false, true] {
                            for has_grants in [false, true] {
                                let grants = if has_grants {
                                    Grants {
                                        session: &names,
                                        permanent: &names,
                                    }
                                } else {
                                    Grants::default()
                                };
                                let result = decide(
                                    Some(&tool(effect, sensitivity)),
                                    &session(mode, untrusted, private),
                                    grants,
                                    &[RuleDecision::Allow],
                                );
                                let requires_human = effect == Effect::External
                                    && untrusted
                                    && (private || sensitivity == Sensitivity::Private);
                                if requires_human {
                                    assert_eq!(
                                        result,
                                        Ok(ask(AskReason::RuleOfTwo, ApprovalScopes::OnceOnly))
                                    );
                                } else {
                                    assert_eq!(
                                        result,
                                        Ok(Decision::Allow(if has_grants {
                                            AllowReason::Grant
                                        } else {
                                            AllowReason::Config
                                        }))
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn grants_are_exact_exposed_names_and_precede_config_ask() {
        let session = session(Mode::Default, false, false);
        let tool = tool(Effect::External, Sensitivity::Public);
        for names in [vec![NAME.into()], vec!["web__fetch".into(), NAME.into()]] {
            for grants in [
                Grants {
                    session: &names,
                    permanent: &[],
                },
                Grants {
                    session: &[],
                    permanent: &names,
                },
            ] {
                assert_eq!(
                    decide(Some(&tool), &session, grants, &[RuleDecision::Ask]),
                    Ok(Decision::Allow(AllowReason::Grant))
                );
            }
        }
        for wrong in [
            "fs-tools__*",
            "read_file",
            "other__read_file",
            "FS-TOOLS__read_file",
            "fs-tools__read_file_suffix",
        ] {
            let names = [wrong.into()];
            assert_eq!(
                decide(
                    Some(&tool),
                    &session,
                    Grants {
                        session: &names,
                        permanent: &names
                    },
                    &[RuleDecision::Ask, RuleDecision::Allow]
                ),
                Ok(ask(AskReason::Config, ApprovalScopes::OnceSessionAlways))
            );
        }
    }

    #[test]
    fn ask_precedes_allow_and_auto_regardless_of_rule_order() {
        for rules in [
            [RuleDecision::Ask, RuleDecision::Allow],
            [RuleDecision::Allow, RuleDecision::Ask],
        ] {
            assert_eq!(
                decide(
                    Some(&tool(Effect::Read, Sensitivity::Public)),
                    &session(Mode::Auto, false, false),
                    Grants::default(),
                    &rules
                ),
                Ok(ask(AskReason::Config, ApprovalScopes::OnceSessionAlways))
            );
        }
    }

    #[test]
    fn known_mode_defaults_do_not_confuse_local_writes_with_external_effects() {
        for mode in [Mode::Default, Mode::Auto] {
            for effect in [Effect::Read, Effect::WriteLocal, Effect::External] {
                let expected = match (mode, effect) {
                    (Mode::Auto, _) => Decision::Allow(AllowReason::AutoMode),
                    (_, Effect::External) => {
                        ask(AskReason::DefaultMode, ApprovalScopes::OnceSessionAlways)
                    }
                    _ => Decision::Allow(AllowReason::DefaultMode),
                };
                assert_eq!(
                    decide(
                        Some(&tool(effect, Sensitivity::Public)),
                        &session(mode, false, false),
                        Grants::default(),
                        &[]
                    ),
                    Ok(expected)
                );
            }
        }
    }

    #[test]
    fn eval_converts_every_ask_but_preserves_prior_denials_allows_and_errors() {
        for mode in [Mode::Plan, Mode::Default, Mode::Auto] {
            for effect in [Effect::Read, Effect::WriteLocal, Effect::External] {
                for sensitivity in [Sensitivity::Public, Sensitivity::Private] {
                    for untrusted in [false, true] {
                        for private in [false, true] {
                            for rules in [
                                vec![],
                                vec![RuleDecision::Ask],
                                vec![RuleDecision::Allow],
                                vec![RuleDecision::Deny],
                            ] {
                                let tool = tool(effect, sensitivity);
                                let normal = session(mode, untrusted, private);
                                let evaluated = Session {
                                    kind: "eval",
                                    ..normal
                                };
                                let expected =
                                    match decide(Some(&tool), &normal, Grants::default(), &rules) {
                                        Ok(Decision::Ask { .. }) => {
                                            Ok(Decision::Deny(DenyReason::EvalWithoutHuman))
                                        }
                                        result => result,
                                    };
                                assert_eq!(
                                    decide(Some(&tool), &evaluated, Grants::default(), &rules),
                                    expected
                                );
                            }
                        }
                    }
                }
            }
        }
    }
}
