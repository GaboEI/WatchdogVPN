from __future__ import annotations

import argparse
import json
from collections.abc import Mapping, Sequence
from typing import Any


INVENTORY_SCHEMA_VERSION = 2
ROOT_ROUTE_SUMMARY = "Canonical WatchdogVPN command root"


class DocumentedPassthroughAction(argparse.Action):
    """Argparse choice action with documented command-route metadata."""

    def __init__(
        self,
        option_strings: Sequence[str],
        dest: str,
        *,
        route_summaries: Mapping[str, str],
        **kwargs: Any,
    ) -> None:
        summaries = dict(route_summaries)
        if not summaries:
            raise ValueError("documented passthrough routes cannot be empty")
        if any(not name or not summary.strip() for name, summary in summaries.items()):
            raise ValueError("documented passthrough routes require names and summaries")
        if "choices" in kwargs:
            raise ValueError("choices are derived from route_summaries")
        self.route_summaries = summaries
        super().__init__(
            option_strings=option_strings,
            dest=dest,
            choices=tuple(summaries),
            **kwargs,
        )

    def __call__(
        self,
        parser: argparse.ArgumentParser,
        namespace: argparse.Namespace,
        values: str | Sequence[str] | None,
        option_string: str | None = None,
    ) -> None:
        del parser, option_string
        setattr(namespace, self.dest, values)


def build_command_inventory(
    parser: argparse.ArgumentParser,
    *,
    cli_name: str = "watchdog",
) -> dict[str, Any]:
    """Build a deterministic public command inventory from an argparse tree."""

    routes: list[dict[str, Any]] = []

    def walk(
        current: argparse.ArgumentParser,
        path: tuple[str, ...],
        summary: str,
    ) -> None:
        subparser_actions = [
            action
            for action in current._actions
            if isinstance(action, argparse._SubParsersAction)
        ]
        passthrough_actions = [
            action
            for action in current._actions
            if isinstance(action, DocumentedPassthroughAction)
        ]
        children = [
            name
            for action in subparser_actions
            for name in action.choices
        ]
        children.extend(
            name
            for action in passthrough_actions
            for name in action.route_summaries
        )
        command = _command_name(cli_name, path)
        if not path:
            kind = "root"
            usage = f"usage: {cli_name} <command> [options]"
        elif children:
            kind = "group"
            usage = _normalized_usage(current, command=command)
        else:
            kind = "command"
            usage = _normalized_usage(current, command=command)

        routes.append(
            {
                "path": list(path),
                "command": command,
                "kind": kind,
                "source": "argparse",
                "summary": summary,
                "usage": usage,
                "help_command": f"{command} --help",
                "children": children,
                "arguments": _public_arguments(current),
                "mutually_exclusive_groups": _public_mutually_exclusive_groups(current),
            }
        )

        for action in subparser_actions:
            help_by_name = {
                choice.dest: choice.help
                for choice in action._choices_actions
            }
            for name, child in action.choices.items():
                child_summary = help_by_name.get(name)
                if not isinstance(child_summary, str) or not child_summary.strip():
                    child_summary = f"Undocumented parser route: {name}"
                walk(child, (*path, name), child_summary)

        for action in passthrough_actions:
            for name, child_summary in action.route_summaries.items():
                child_path = (*path, name)
                child_command = _command_name(cli_name, child_path)
                routes.append(
                    {
                        "path": list(child_path),
                        "command": child_command,
                        "kind": "passthrough",
                        "source": "documented-passthrough-choice",
                        "summary": child_summary,
                        "usage": f"usage: {child_command} [arguments ...]",
                        "help_command": f"{child_command} --help",
                        "children": [],
                        "arguments": [
                            {
                                "name": "arguments",
                                "kind": "positional",
                                "required": False,
                                "cardinality": "remainder",
                                "choices": [],
                                "description": "Arguments forwarded to the maintenance backend",
                            }
                        ],
                        "mutually_exclusive_groups": [],
                    }
                )

    walk(parser, (), ROOT_ROUTE_SUMMARY)
    parser_route_count = sum(route["source"] == "argparse" for route in routes)
    passthrough_route_count = len(routes) - parser_route_count
    group_route_count = sum(route["kind"] in {"root", "group"} for route in routes)
    return {
        "schema_version": INVENTORY_SCHEMA_VERSION,
        "cli": cli_name,
        "route_count": len(routes),
        "command_route_count": len(routes) - 1,
        "parser_route_count": parser_route_count,
        "passthrough_route_count": passthrough_route_count,
        "group_route_count": group_route_count,
        "leaf_route_count": len(routes) - group_route_count,
        "routes": routes,
    }


def render_inventory_json(inventory: Mapping[str, Any]) -> str:
    """Render the machine-readable inventory snapshot."""

    return json.dumps(inventory, indent=2, ensure_ascii=False) + "\n"


def render_inventory_markdown(inventory: Mapping[str, Any]) -> str:
    """Render a complete human-readable route and argument inventory."""

    lines = [
        "# Generated WatchdogVPN CLI Command Inventory",
        "",
        "> Generated from `cli.main._build_parser()` by",
        "> `scripts/generate_cli_inventory.py`. Do not edit this file manually.",
        "",
        "Regenerate both committed snapshots:",
        "",
        "```sh",
        "python3 scripts/generate_cli_inventory.py",
        "```",
        "",
        "Verify parser/documentation parity without writing files:",
        "",
        "```sh",
        "python3 scripts/generate_cli_inventory.py --check",
        "```",
        "",
        "Only public parser arguments are included. Internal test and recovery-path",
        "overrides whose argparse help is suppressed remain intentionally absent.",
        "",
        "## Snapshot",
        "",
        f"- Schema version: `{inventory['schema_version']}`",
        f"- Routes including the canonical root: `{inventory['route_count']}`",
        f"- Command routes excluding the root: `{inventory['command_route_count']}`",
        f"- Argparse-backed routes: `{inventory['parser_route_count']}`",
        f"- Documented maintenance passthrough routes: `{inventory['passthrough_route_count']}`",
        f"- Group/root routes: `{inventory['group_route_count']}`",
        f"- Leaf routes: `{inventory['leaf_route_count']}`",
        "",
        "## Route Index",
        "",
        "| # | Route | Kind | Source | Summary |",
        "|---:|---|---|---|---|",
    ]
    routes = inventory["routes"]
    for index, route in enumerate(routes, start=1):
        lines.append(
            "| "
            f"{index} | `{_escape_markdown(route['command'])}` | "
            f"{_escape_markdown(route['kind'])} | "
            f"{_escape_markdown(route['source'])} | "
            f"{_escape_markdown(route['summary'])} |"
        )

    lines.extend(["", "## Route Contracts", ""])
    for index, route in enumerate(routes, start=1):
        lines.extend(
            [
                f"### {index}. `{route['command']}`",
                "",
                f"- Kind: `{route['kind']}`",
                f"- Source: `{route['source']}`",
                f"- Summary: {route['summary']}",
                f"- Help: `{route['help_command']}`",
            ]
        )
        if route["children"]:
            children = ", ".join(f"`{child}`" for child in route["children"])
            lines.append(f"- Direct child routes: {children}")
        mutually_exclusive_groups = route["mutually_exclusive_groups"]
        if mutually_exclusive_groups:
            lines.append("- Mutually exclusive argument groups:")
            for group in mutually_exclusive_groups:
                requirement = "required" if group["required"] else "optional"
                members = ", ".join(f"`{member}`" for member in group["members"])
                lines.append(f"  - {requirement}: {members}")
        lines.extend(
            [
                "",
                "Usage:",
                "",
                "```text",
                route["usage"],
                "```",
                "",
            ]
        )
        arguments = route["arguments"]
        if not arguments:
            lines.extend(["Public route-specific arguments: none.", ""])
            continue
        lines.extend(
            [
                "| Argument | Kind | Required | Cardinality | Choices | Description |",
                "|---|---|---|---|---|---|",
            ]
        )
        for argument in arguments:
            choices = ", ".join(str(choice) for choice in argument["choices"]) or "—"
            description = argument["description"] or "—"
            lines.append(
                "| "
                f"`{_escape_markdown(argument['name'])}` | "
                f"{_escape_markdown(argument['kind'])} | "
                f"{'yes' if argument['required'] else 'no'} | "
                f"{_escape_markdown(argument['cardinality'])} | "
                f"{_escape_markdown(choices)} | "
                f"{_escape_markdown(description)} |"
            )
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def _command_name(cli_name: str, path: tuple[str, ...]) -> str:
    return " ".join((cli_name, *path))


def _normalized_usage(
    parser: argparse.ArgumentParser,
    *,
    command: str,
) -> str:
    structured_usage = _structured_required_optional_positional_mutex_usage(
        parser,
        command=command,
    )
    if structured_usage is not None:
        return structured_usage

    # Inventory records the parser's canonical syntax, independent of the
    # active terminal width and its human-facing responsive reflow.
    rendered = argparse.ArgumentParser.format_usage(parser)
    rendered = rendered.replace(
        f"usage: {parser.prog}",
        f"usage: {command}",
        1,
    )
    rendered = " ".join(rendered.strip().split())
    return rendered


def _public_arguments(parser: argparse.ArgumentParser) -> list[dict[str, Any]]:
    arguments: list[dict[str, Any]] = []
    for action in parser._actions:
        if isinstance(
            action,
            (argparse._HelpAction, argparse._SubParsersAction, DocumentedPassthroughAction),
        ):
            continue
        if action.help == argparse.SUPPRESS:
            continue
        name, kind = _public_action_name_and_kind(action)
        choices = [] if action.choices is None else [str(choice) for choice in action.choices]
        arguments.append(
            {
                "name": name,
                "kind": kind,
                "required": _action_is_required(action),
                "cardinality": _cardinality(action.nargs),
                "choices": choices,
                "description": "" if action.help is None else str(action.help),
            }
        )
    return arguments


def _public_mutually_exclusive_groups(parser: argparse.ArgumentParser) -> list[dict[str, Any]]:
    """Return public mutex semantics without argparse usage-rendering details."""
    groups: list[dict[str, Any]] = []
    for group in parser._mutually_exclusive_groups:
        members = [
            _public_action_name_and_kind(action)[0]
            for action in group._group_actions
            if _is_public_action(action)
        ]
        if members:
            groups.append({"required": bool(group.required), "members": members})
    return groups


def _is_public_action(action: argparse.Action) -> bool:
    return not isinstance(
        action,
        (argparse._HelpAction, argparse._SubParsersAction, DocumentedPassthroughAction),
    ) and action.help != argparse.SUPPRESS


def _public_action_name_and_kind(action: argparse.Action) -> tuple[str, str]:
    if action.option_strings:
        return ", ".join(action.option_strings), "option"
    return _metavar(action) or action.dest, "positional"


def _action_is_required(action: argparse.Action) -> bool:
    """Return stable public requiredness rather than argparse's private state.

    ``nargs='*'`` and ``argparse.REMAINDER`` are empty by definition. Some
    Python releases expose inconsistent ``Action.required`` internals for
    them, so the inventory derives their public contract directly.
    """
    if action.nargs in {"*", argparse.REMAINDER}:
        return False
    return bool(action.required)


def _structured_required_optional_positional_mutex_usage(
    parser: argparse.ArgumentParser,
    *,
    command: str,
) -> str | None:
    """Build the exceptional required mutex usage without ``argparse`` text.

    A required mutually-exclusive group which includes an optional positional
    has stable semantics but no stable ``format_usage()`` representation across
    Python releases.  Its inventory usage is therefore constructed from the
    public parser structure (members and requiredness), never by repairing the
    renderer's string after the fact.
    """
    groups = [
        group
        for group in parser._mutually_exclusive_groups
        if group.required
        and any(
            not action.option_strings and action.nargs == "?"
            for action in group._group_actions
        )
    ]
    if len(groups) != 1:
        return None

    group = groups[0]
    group_actions = set(group._group_actions)
    tokens: list[str] = []
    for action in parser._actions:
        if action in group_actions or action.help == argparse.SUPPRESS:
            continue
        token = _usage_action_token(action)
        if token is None:
            continue
        tokens.append(token if _action_is_required(action) else f"[{token}]")

    members = sorted(
        group._group_actions,
        key=lambda action: (not bool(action.option_strings), action.dest),
    )
    tokens.append(f"({' | '.join(_usage_member_name(action) for action in members)})")
    return f"usage: {command} {' '.join(tokens)}"


def _usage_action_token(action: argparse.Action) -> str | None:
    """Render the public syntax of one action from its declared structure."""
    if isinstance(action, (argparse._SubParsersAction, DocumentedPassthroughAction)):
        return None
    if isinstance(action, argparse._HelpAction):
        return "-h"

    name = _usage_member_name(action)
    if action.nargs == 0:
        return name

    value = _usage_value_name(action)
    if action.nargs is None:
        return f"{name} {value}" if action.option_strings else value
    if action.nargs == "?":
        return f"{name} [{value}]" if action.option_strings else f"[{value}]"
    if action.nargs == "+":
        return f"{name} {value} [{value} ...]" if action.option_strings else f"{value} [{value} ...]"
    if action.nargs in {"*", argparse.REMAINDER}:
        return f"{name} [{value} ...]" if action.option_strings else f"[{value} ...]"
    if isinstance(action.nargs, int):
        values = " ".join(value for _ in range(action.nargs))
        return f"{name} {values}" if action.option_strings else values
    return None


def _usage_value_name(action: argparse.Action) -> str:
    if action.choices is not None:
        return "{" + ",".join(str(choice) for choice in action.choices) + "}"
    return _metavar(action) or action.dest.upper()


def _usage_member_name(action: argparse.Action) -> str:
    if action.option_strings:
        return max(action.option_strings, key=len)
    return _metavar(action) or action.dest


def _metavar(action: argparse.Action) -> str | None:
    if action.metavar is None:
        return None
    if isinstance(action.metavar, tuple):
        return " ".join(str(value) for value in action.metavar)
    return str(action.metavar)


def _cardinality(nargs: str | int | None) -> str:
    if nargs == 0:
        return "flag"
    labels = {
        None: "one",
        "?": "zero-or-one",
        "*": "zero-or-more",
        "+": "one-or-more",
        argparse.REMAINDER: "remainder",
    }
    if nargs in labels:
        return labels[nargs]
    return str(nargs)


def _escape_markdown(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")
