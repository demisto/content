import dataclasses
import http
import inspect
from collections import defaultdict
from datetime import datetime, timedelta
from email.utils import parsedate_to_datetime
from functools import wraps
from typing import Any, Callable, Optional, TypeVar

import demistomock as demisto  # noqa: F401
import urllib3
from CommonServerPython import *  # noqa: F401

# Disable insecure warnings
urllib3.disable_warnings()


""" CONSTANTS """

VENDOR = "forcepoint"
PRODUCT = "forcepoint_dlp"
DEFAULT_MAX_FETCH = 10000
API_DEFAULT_LIMIT = 10000
MAX_GET_IDS_CHUNK_SIZE = 1000
DEFAULT_TEST_MODULE_SINCE_TIME = "3 days"
DATEPARSER_SETTINGS = {
    "RETURN_AS_TIMEZONE_AWARE": True,
    "TIMEZONE": "UTC",
}
DATE_TIME_FORMAT = "%d/%m/%Y %H:%M:%S"
DictOrList = TypeVar("DictOrList", list, dict)

""" CLIENT CLASS """


def to_str_time(t: datetime) -> str:
    return t.strftime(DATE_TIME_FORMAT)


def from_str_time(s: str) -> datetime:
    return datetime.strptime(s, DATE_TIME_FORMAT)


NO_CONTENT_CODE = 420
NO_CONTENT_MESSAGE = "No data to show"
MISSING_RULE_NAME = "The argument 'rule_name' is required when using policy_name."
DATE_FORMAT = "%d/%m/%Y %H:%M:%S"
XSOAR_DATE_FORMAT = "%Y-%m-%dT%H:%M:%S.000Z"
MIRRORING_FIELDS = [
    "status",
    "severity",
    "false_positive",
]
INTEGRATION_NAME = "fp-dlp"
INCIDENT_UPDATE_MAPPER = [
    ("status", "STATUS"),
    ("assign", "ASSIGN_TO"),
    ("tag", "TAG"),
    ("severity", "SEVERITY"),
    ("release", "RELEASE"),
    ("false_positive", "FALSE_POSITIVE"),
]
INTEGRATION_PREFIX = "ForcepointDlp"
CLASSIFIER_HEADERS = [
    "predefined",
    "position",
    "threshold_type",
    "threshold_value_from",
    "threshold_value_to",
    "threshold_calculate_type",
]
RULE_EXCEPTION_HEADERS = [
    "exception_rule_name",
    "enabled",
    "description",
    "display_description",
    "condition_enabled",
    "destination_enabled",
]
INCIDENT_HEADERS = [
    "id",
    "event_id",
    "severity",
    "action",
    "status",
    "source_ip_address",
    "event_time",
    "channel",
    "tag",
    "assigned_to",
]
MIRROR_DIRECTION_MAPPING = {
    "None": None,
    "Incoming": "In",
    "Outgoing": "Out",
    "Incoming And Outgoing": "Both",
}
FP_XSOAR_SEVERITY_MAPPER = {
    "LOW": 2,
    "MEDIUM": 3,
    "HIGH": 4,
}
XSOAR_FP_SEVERITY_MAPPER = {
    0: "LOW",
    1: "LOW",
    2: "LOW",
    3: "MEDIUM",
    4: "HIGH",
    5: "HIGH",
}
DEFAULT_LIMIT = 50

@dataclasses.dataclass
class Classifier:
    """
    Represents a classifier inside a rule
    """

    classifier_name: str
    predefined: str
    position: int
    threshold_type: str
    threshold_value_from: int
    threshold_calculate_type: str
    threshold_value_to: Optional[int] = None

    def __post_init__(self) -> None:
        if self.threshold_type == "CHECK_IN_RANGE" and self.threshold_value_to is None:
            raise DemistoException(
                f"Field 'threshold_value_to' for classifier {self.classifier_name} cannot be None."
            )
        if (
            self.threshold_value_to
            and self.threshold_type == "CHECK_IN_RANGE"
            and self.threshold_value_from > self.threshold_value_to
        ):
            raise DemistoException(
                f"Field 'threshold_value_from' for classifier {self.classifier_name}"
                " should be lower than field 'threshold_value_to'."
            )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Classifier":
        """Create an object from a given dict."""
        return cls(**{k: v for k, v in data.items() if k in inspect.signature(cls).parameters})

    @classmethod
    def from_args(cls, args: dict[str, Any]) -> "Classifier":
        """Create an object from given user arguments."""
        return cls(
            classifier_name=args.get("classifier_name"),
            predefined=args.get("classifier_predefined"),
            position=arg_to_number(args.get("classifier_position")),
            threshold_type=args.get("classifier_threshold_type"),
            threshold_value_from=arg_to_number(args.get("classifier_threshold_value_from")),
            threshold_calculate_type=args.get("classifier_threshold_calculate_type"),
            threshold_value_to=arg_to_number(args.get("classifier_threshold_value_to")),
        )

    def update_from_args(self, args: dict[str, Any]) -> None:
        """Update an object from given user arguments."""
        if "classifier_name" in args:
            self.classifier_name = args["classifier_name"]
        if "classifier_predefined" in args:
            self.predefined = args["classifier_predefined"]
        if "classifier_position" in args:
            self.position = args["classifier_position"]
        if "threshold_type" in args:
            self.threshold_type = args["threshold_type"]
        if "threshold_value_from" in args:
            self.threshold_value_from = args["threshold_value_from"]
        if "threshold_value_to" in args:
            self.threshold_calculate_type = args["threshold_value_to"]
        if "threshold_calculate_type" in args:
            self.threshold_value_to = args["threshold_calculate_type"]


@dataclasses.dataclass
class SeverityActionClassifier:
    """
    Represents severity and action classifier.
    """

    number_of_matches: int
    selected: str
    severity_type: str
    action_plan: str
    dup_severity_type: str

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SeverityActionClassifier":
        """Create an object from a given dict."""
        return cls(**{k: v for k, v in data.items() if k in inspect.signature(cls).parameters})

    @classmethod
    def from_args(cls, args: dict[str, Any]) -> "SeverityActionClassifier":
        """Create an object from given user arguments."""
        return cls(
            number_of_matches=arg_to_number(args.get("severity_classifier_number_of_matches")),
            selected=args.get("severity_classifier_selected"),
            severity_type=args.get("severity_classifier_severity_type"),
            dup_severity_type=args.get("severity_classifier_severity_type"),
            action_plan=args.get("severity_classifier_action_plan"),
        )

    def update_from_args(self, args: dict[str, Any]) -> None:
        """Update an object from given user arguments."""
        if "severity_classifier_number_of_matches" in args:
            self.number_of_matches = arg_to_number(args["severity_classifier_number_of_matches"])
        if "severity_classifier_selected" in args:
            self.selected = args["severity_classifier_selected"]
        if "severity_classifier_severity_type" in args:
            self.severity_type = args["severity_classifier_severity_type"]
            self.dup_severity_type = args["severity_classifier_severity_type"]
        if "severity_classifier_action_plan" in args:
            self.action_plan = args["severity_classifier_action_plan"]


@dataclasses.dataclass
class Rule:
    """
    Represents a policy rule.
    """

    rule_name: str
    enabled: str
    parts_count_type: str
    condition_relation_type: str
    classifiers: list[Classifier]

    def __post_init__(self) -> None:
        if not self.classifiers:
            raise DemistoException(f"Rule '{self.rule_name}' must have at least one classifier.")

        positions = []
        for classifier in self.classifiers:
            positions.append(classifier.position)

        if len(set(positions)) < len(self.classifiers):
            raise DemistoException("The classifier position already exists.")

        if set(range(1, len(self.classifiers) + 1)) != set(positions):
            raise DemistoException("Invalid classifier position.")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Rule":
        """Create an object from a given dict."""
        classifiers = data.pop("classifiers", [])
        return cls(
            **{k: v for k, v in data.items() if k in inspect.signature(cls).parameters},
            classifiers=[Classifier.from_dict(classifier) for classifier in classifiers],
        )

    @classmethod
    def from_args(cls, args: dict[str, Any]) -> "Rule":
        """Create an object from given user arguments."""
        return cls(
            rule_name=args.get("rule_name"),
            enabled=args.get("rule_enabled"),
            parts_count_type=args.get("rule_parts_count_type"),
            condition_relation_type=args.get("rule_condition_relation_type"),
            classifiers=[Classifier.from_args(args)],
        )

    def update_from_args(self, args: dict[str, Any]) -> None:
        """Update an object from given user arguments."""
        if "rule_name" in args:
            self.rule_name = args["rule_name"]
        if "rule_enabled" in args:
            self.enabled = args["rule_enabled"]
        if "rule_parts_count_type" in args:
            self.parts_count_type = args["rule_parts_count_type"]
        if "rule_condition_relation_type" in args:
            self.condition_relation_type = args["rule_condition_relation_type"]

        position = args.get("classifier_position")
        if position is not None and (classifier := self.find_classifier(position)):
            classifier.update_from_args(args)
        else:
            self.classifiers.append(Classifier.from_args(args))

    def find_classifier(self, position: int) -> Classifier | None:
        """Find a classifier by position.

        Args:
            position (int): The position of the classifier.

        Returns:
            Classifier | None: The classifier if found, otherwise None.
        """
        for classifier in self.classifiers:
            if classifier.position == position:
                return classifier

        return None

@dataclasses.dataclass
class SeverityActionException:
    """
    Represents a severity and action exception in rule.
    """

    max_matches: str
    classifier_details: list[SeverityActionClassifier]

    def __post_init__(self) -> None:
        if len(self.classifier_details) > 3:
            raise DemistoException(
                "The maximum number of classifiers is 3."
                " Use `override_severity_classifier_number_of_matches` to override another classifier."
            )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SeverityActionException":
        """Create an object from a given dict."""
        classifier_details = data.pop("classifier_details", [])
        return cls(
            max_matches=data.get("max_matches"),
            classifier_details=[SeverityActionClassifier.from_dict(classifier) for classifier in classifier_details],
        )

    @classmethod
    def from_args(cls, args: dict[str, Any]) -> "SeverityActionException":
        """Create an object from given user arguments."""
        classifier_details: list[SeverityActionClassifier] = []

        for i in range(0, 3):
            classifier_details.append(SeverityActionClassifier.from_args(args))

            if i != 0:
                classifier_details[i].selected = "false"

        return cls(
            max_matches=args.get("severity_classifier_max_matches"),
            classifier_details=classifier_details,
        )

    def update_from_args(self, args: dict[str, Any]) -> None:
        """Update an object from given user arguments."""
        if "severity_classifier_max_matches" in args:
            self.max_matches = args["severity_classifier_max_matches"]

        number_of_matches = arg_to_number(args.get("severity_classifier_number_of_matches"))
        override_number_of_matches = arg_to_number(args.get("override_severity_classifier_number_of_matches"))

        if override_number_of_matches is not None:
            search_number = override_number_of_matches
        else:
            search_number = number_of_matches

        classifier_detail = self.find_classifier_details(search_number)

        if classifier_detail:
            classifier_detail.update_from_args(args)
        else:
            if search_number:
                raise DemistoException(f"{search_number} does not exists in the classifiers `number_of_matches`")

            self.classifier_details.append(SeverityActionClassifier.from_args(args))

        self.classifier_details.sort(
            key=lambda x: (x.number_of_matches is None, x.number_of_matches or 0),
            reverse=True,
        )

    def find_classifier_details(self, number_of_matches: int) -> SeverityActionClassifier | None:
        """Find a classifier by number of matches.

        Args:
            number_of_matches (int): The number of matches of the classifier.

        Returns:
            SeverityActionClassifier | None: The classifier if found, otherwise None.
        """
        for classifier_detail in self.classifier_details:
            if classifier_detail.number_of_matches == number_of_matches:
                return classifier_detail

        return None

@dataclasses.dataclass
class ExceptionRule:
    """
    Represents an exception of a rule.
    """

    exception_rule_name: str
    enabled: str
    condition_enabled: str
    source_enabled: str
    destination_enabled: str
    parts_count_type: str
    condition_relation_type: str
    classifiers: list[Classifier]
    severity_action: SeverityActionException
    description: Optional[str] = None
    display_description: Optional[str] = None

    def __post_init__(self) -> None:
        if not self.classifiers:
            raise DemistoException(
                f"Exception Rule '{self.exception_rule_name}' must have at least one classifier."
            )

        positions = []
        for classifier in self.classifiers:
            positions.append(classifier.position)

        if len(set(positions)) < len(self.classifiers):
            raise DemistoException("The classifier position already exists.")

        if set(range(1, len(self.classifiers) + 1)) != set(positions):
            raise DemistoException("Invalid classifier position.")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ExceptionRule":
        """Create an object from a given dict."""
        classifiers = data.pop("classifiers", [])
        severity_action = data.pop("severity_action", {})
        return cls(
            exception_rule_name=data.get("exception_rule_name"),
            enabled=data.get("enabled"),
            condition_enabled=data.get("condition_enabled"),
            source_enabled="false",
            destination_enabled="false",
            parts_count_type=data.get("parts_count_type"),
            condition_relation_type=data.get("condition_relation_type"),
            classifiers=[Classifier.from_dict(classifier) for classifier in classifiers],
            severity_action=SeverityActionException.from_dict(severity_action),
            description=data.get("description"),
            display_description=data.get("display_description"),
        )

    @classmethod
    def from_args(cls, args: dict[str, Any]) -> "ExceptionRule":
        """Create an object from given user arguments."""
        return cls(
            exception_rule_name=args.get("exception_rule_name"),
            enabled=args.get("enabled"),
            condition_enabled=args.get("condition_enabled"),
            source_enabled="false",
            destination_enabled="false",
            parts_count_type=args.get("parts_count_type"),
            condition_relation_type=args.get("condition_relation_type"),
            classifiers=[Classifier.from_args(args)],
            severity_action=SeverityActionException.from_args(args),
            description=args.get("description"),
            display_description=args.get("description"),
        )

    def update_from_args(self, args: dict[str, Any]) -> "ExceptionRule":
        """Update an object from given user arguments."""
        if "exception_rule_name" in args:
            self.exception_rule_name = args["exception_rule_name"]
        if "enabled" in args:
            self.enabled = args["enabled"]
        if "condition_enabled" in args:
            self.condition_enabled = args["condition_enabled"]
        if "parts_count_type" in args:
            self.parts_count_type = args["parts_count_type"]
        if "condition_relation_type" in args:
            self.condition_relation_type = args["condition_relation_type"]
        if "description" in args:
            self.description = args["description"]
            self.display_description = args["description"]

        position = arg_to_number(args.get("classifier_position"))
        if position is not None and (classifier := self.find_classifier(position)):
            classifier.update_from_args(args)
        else:
            self.classifiers.append(Classifier.from_args(args))

        self.severity_action.update_from_args(args)

    def find_classifier(self, position: int) -> Classifier | None:
        """Find a classifier by position.

        Args:
            position (int): The position of the classifier.

        Returns:
            Classifier | None: The classifier if found, otherwise None.
        """
        for classifier in self.classifiers:
            if classifier.position == position:
                return classifier

        return None


@dataclasses.dataclass
class SeverityActionRule:
    """
    Represents severity and action settings in rule.
    """

    rule_name: str
    type: str
    max_matches: str
    classifier_details: list[SeverityActionClassifier]
    risk_adaptive_protection_enabled: str
    count_type: Optional[str] = None
    count_time_period: Optional[str] = None
    count_time_period_window: Optional[str] = None

    def __post_init__(self) -> None:
        if self.type == "CUMULATIVE_CONDITION" and not self.count_type:
            raise DemistoException(
                "The field `rule_count_type` is required when the type is `CUMULATIVE_CONDITION`."
            )
        if self.type == "CUMULATIVE_CONDITION" and not self.count_time_period:
            raise DemistoException(
                "The field `count_time_period` is required when the type is `CUMULATIVE_CONDITION`."
            )
        if self.type == "CUMULATIVE_CONDITION" and not self.count_time_period_window:
            raise DemistoException(
                "The field `rule_rate_match_period` is required when the type is `CUMULATIVE_CONDITION`."
            )

        if len(self.classifier_details) > 3:
            raise DemistoException(
                "The maximum number of classifiers is 3."
                " Use `override_severity_classifier_number_of_matches` to override another classifier."
            )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SeverityActionRule":
        """Create an object from a given dict."""
        classifiers = data.pop("classifier_details", [])
        return cls(
            **{k: v for k, v in data.items() if k in inspect.signature(cls).parameters},
            classifier_details=[SeverityActionClassifier.from_dict(classifier) for classifier in classifiers],
        )

    def update_from_args(self, args: dict[str, Any]) -> None:
        """Update an object from given user arguments."""
        self.risk_adaptive_protection_enabled = "false"

        if "rule_name" in args:
            self.rule_name = args["rule_name"]
        if "rule_type" in args:
            self.type = args["rule_type"]
        if "rule_max_matches" in args:
            self.max_matches = args["rule_max_matches"]

        if args.get("rule_type") == "CUMULATIVE_CONDITION":
            if "rule_count_type" in args:
                self.count_type = args["rule_count_type"]
            if "rule_count_period" in args:
                self.count_time_period = args["rule_count_period"]
            if "rule_rate_match_period" in args:
                self.count_time_period_window = args["rule_rate_match_period"]

        if self.classifier_details:
            number_of_matches = arg_to_number(args.get("severity_classifier_number_of_matches"))
            override_number_of_matches = arg_to_number(args.get("override_severity_classifier_number_of_matches"))

            if override_number_of_matches is not None:
                search_number = override_number_of_matches
            else:
                search_number = number_of_matches

            classifier = self.find_classifier(search_number)

            if not classifier and search_number:
                raise DemistoException(f"{search_number} does not exists in the classifiers `number_of_matches`")

            classifier.update_from_args(args)
            self.classifier_details.sort(
                key=lambda x: (x.number_of_matches is None, x.number_of_matches or 0),
                reverse=True,
            )
        else:
            for i in range(0, 3):
                self.classifier_details.append(SeverityActionClassifier.from_args(args))

                if i != 0:
                    self.classifier_details[i].selected = "false"

    def find_classifier(self, number_of_matches: int) -> SeverityActionClassifier | None:
        """Find a classifier by position.

        Args:
            position (int): The position of the classifier.

        Returns:
            Classifier | None: The classifier if found, otherwise None.
        """
        for classifier in self.classifier_details:
            if classifier.number_of_matches == number_of_matches:
                return classifier

        return None

@dataclasses.dataclass
class Resource:
    """
    Represents a resoure in rule.
    """

    resource_name: str
    type: str
    include: Optional[str]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Resource":
        """Create an object from a given dict."""
        return cls(
            resource_name=data.get("resource_name"),
            type=data.get("type"),
            include=data.get("include"),
        )

    @classmethod
    def from_args(cls, args: dict[str, Any]) -> "Resource":
        """Create an object from given user arguments."""
        return cls(
            resource_name=args.get("resource_name"),
            type=args.get("resource_type"),
            include=args.get("resource_include"),
        )

    def update_from_args(self, args: dict[str, Any]) -> None:
        """Update an object from given user arguments."""
        if "resource_type" in args:
            self.type = args["resource_type"]
        if "resource_include" in args:
            self.include = args["resource_include"]


@dataclasses.dataclass
class Channel:
    """
    Represents a channel in rule source and destination.
    """

    channel_type: str
    enabled: str
    resources: list[Resource] = dataclasses.field(default_factory=list)
    user_operations: list[str] = dataclasses.field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RuleDestination":
        """Create an object from a given dict."""
        resources = data.pop("resources", [])
        return cls(
            channel_type=data.get("channel_type"),
            enabled=data.get("enabled"),
            resources=[Resource.from_dict(resource) for resource in resources],
            user_operations=data.get("user_operations", []),
        )

    @classmethod
    def from_args(cls, args: dict[str, Any]) -> "RuleDestination":
        """Create an object from given user arguments."""
        return cls(
            channel_type=args.get("channel_type"),
            enabled=args.get("channel_enabled"),
            resources=[Resource.from_args(args)],
        )

    def update_from_args(self, args: dict[str, Any]) -> None:
        """Update an object from given user arguments."""
        if "channel_enabled" in args:
            self.enabled = args["channel_enabled"]

        resource_name  = args.get("resource_name")
        resource = self.find_resource(resource_name)

        if resource:
            resource.update_from_args(args)
        else:
            self.resources.append(Resource.from_args(args))

    def find_resource(self, resource_name: str) -> Resource | None:
        """Find a resource by name.

        Args:
            resource_name (str): The name of the resource.

        Returns:
            Resource | None: The resource if found, otherwise None.
        """
        for resource in self.resources:
            if resource.resource_name == resource_name:
                return resource

        return None


@dataclasses.dataclass
class RuleDestination:
    """
    Represents destination settings in source and destination rule.
    """

    email_monitor_directions: list[str]
    channels: list[Channel]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RuleDestination":
        """Create an object from a given dict."""
        channels = data.pop("channels", [])
        return cls(
            email_monitor_directions=data.get("email_monitor_directions", []),
            channels=[Channel.from_dict(channel) for channel in channels],
        )

    def update_from_args(self, args: dict[str, Any]) -> None:
        """Update an object from given user arguments."""
        if "rule_destination_email_monitor_directions" in args:
            self.email_monitor_directions = argToList(args["rule_destination_email_monitor_directions"])

        channel = self.find_channel(args.get("channel_type"))

        if channel:
            channel.update_from_args(args)
        else:
            self.channels.append(Channel.from_args(args))

    def find_channel(self, channel_type: str) -> Channel | None:
        """Find a channel by type.

        Args:
            channel_type (str): The type of the channel.

        Returns:
            Channel | None: The channel if found, otherwise None.
        """
        for channel in self.channels:
            if channel.channel_type == channel_type:
                return channel

        return None


@dataclasses.dataclass
class RuleSource:
    """
    Represents source settings in source and destination rule.
    """

    endpoint_channel_machine_type: str
    endpoint_connection_type: str
    resources: list[Resource] = dataclasses.field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RuleSource":
        """Create an object from a given dict."""
        resources = data.pop("resources", [])
        return cls(
            endpoint_channel_machine_type=data.get("endpoint_channel_machine_type"),
            endpoint_connection_type=data.get("endpoint_connection_type"),
            resources=[Resource.from_dict(resource) for resource in resources],
        )

    def update_from_args(self, args: dict[str, Any]) -> None:
        """Update an object from given user arguments."""
        if "rule_source_endpoint_channel_machine_type" in args:
            self.endpoint_channel_machine_type = args["rule_source_endpoint_channel_machine_type"]
        if "rule_source_endpoint_connection_type" in args:
            self.endpoint_connection_type = args["rule_source_endpoint_connection_type"]

@dataclasses.dataclass
class SourceDestinationRule:
    """
    Represents source and destination settings rule.
    """

    rule_name: str
    rule_source: RuleSource
    rule_destination: RuleDestination

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SourceDestinationRule":
        """Create an object from a given dict."""
        rule_source = data.pop("rule_source", {})
        rule_destination = data.pop("rule_destination", {})
        return cls(
            rule_name=data.get("rule_name"),
            rule_source=RuleSource.from_dict(rule_source),
            rule_destination=RuleDestination.from_dict(rule_destination),
        )

    def update_from_args(self, args: dict[str, Any]) -> None:
        """Update an object from given user arguments."""
        self.rule_source.update_from_args(args)
        self.rule_destination.update_from_args(args)

@dataclasses.dataclass
class PolicyLevel:
    """
    Represents the rule policy level.
    """

    level: int
    data_type: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PolicyLevel":
        """Create an object from a given dict."""
        return cls(**{k: v for k, v in data.items() if k in inspect.signature(cls).parameters})

    @classmethod
    def from_args(cls, args: dict[str, Any]) -> "PolicyLevel":
        """Create an object from given user arguments."""
        return cls(
            level=arg_to_number(args.get("policy_level")),
            data_type=args.get("policy_data_type"),
        )

    def update_from_args(self, args: dict[str, Any]) -> None:
        """Update an object from given user arguments."""
        if "policy_level" in args:
            self.level = args["policy_level"]
        if "policy_data_type" in args:
            self.data_type = args["policy_data_type"]


@dataclasses.dataclass
class PolicyRule:
    """
    Represents a rule in policy.
    """

    dlp_version: str
    policy_name: str
    enabled: str
    predefined_policy: str
    description: str
    policy_level: PolicyLevel
    rules: list[Rule]

    def __post_init__(self) -> None:
        if not self.rules:
            raise DemistoException("Policy must have at least one rule.")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PolicyRule":
        """Create an object from a given dict."""
        policy_level = data.pop("policy_level", {})
        rules = data.pop("rules", [])

        return cls(
            **{k: v for k, v in data.items() if k in inspect.signature(cls).parameters},
            policy_level=PolicyLevel.from_dict(policy_level),
            rules=[Rule.from_dict(rule) for rule in rules],
        )

    @classmethod
    def from_args(cls, args: dict[str, Any]) -> "PolicyRule":
        """Create an object from given user arguments."""
        return cls(
            dlp_version=args.get("dlp_version"),
            policy_name=args.get("policy_name"),
            enabled=args.get("policy_enabled"),
            predefined_policy=args.get("predefined_policy"),
            description=args.get("policy_description", ""),
            policy_level=PolicyLevel.from_args(args),
            rules=[Rule.from_args(args)],
        )

    def update_from_args(self, args: dict[str, Any]) -> None:
        """Update an object from given user arguments."""
        if "dlp_version" in args:
            self.dlp_version = args["dlp_version"]
        if "policy_name" in args:
            self.policy_name = args["policy_name"]
        if "policy_enabled" in args:
            self.enabled = args["policy_enabled"]
        if "predefined_policy" in args:
            self.predefined_policy = args["predefined_policy"]
        if "policy_description" in args:
            self.description = args["policy_description"]

        if "policy_level" in args or "policy_data_type" in args:
            self.policy_level.update_from_args(args)

        rule_name = args.get("rule_name")
        if rule_name is not None and (rule := self.find_rule(rule_name)):
            rule.update_from_args(args)
        else:
            self.rules.append(Rule.from_args(args))

    def find_rule(self, rule_name: str) -> Rule | None:
        """Find a rule by name.

        Args:
            rule_name (str): The name of the rule.

        Returns:
            Rule | None: The rule if found, otherwise None.
        """
        for rule in self.rules:
            if rule.rule_name == rule_name:
                return rule

        return None


@dataclasses.dataclass
class PolicySeverityAction:
    """
    Represents severity and action rule.
    """

    policy_name: str
    rules: list[SeverityActionRule]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PolicySeverityAction":
        """Create an object from a given dict."""
        rules = data.pop("rules", [])
        return cls(
            policy_name=data.get("policy_name"),
            rules=[SeverityActionRule.from_dict(rule) for rule in rules],
        )

    def update_from_args(self, args: dict[str, Any]) -> None:
        """Update an object from given user arguments."""
        if "policy_name" in args:
            self.policy_name = args["policy_name"]

        rule_name = args["rule_name"]
        rule = self.find_rule(rule_name)

        if not rule:
            raise DemistoException(f"Rule `{rule_name}` not found.")

        rule.update_from_args(args)

    def find_rule(self, rule_name: str) -> SeverityActionRule | None:
        """Find a rule by name.

        Args:
            rule_name (str): The name of the rule.

        Returns:
            SeverityActionRule | None: The rule if found, otherwise None.
        """
        for rule in self.rules:
            if rule.rule_name == rule_name:
                return rule

        return None


@dataclasses.dataclass
class PolicySourceDestination:
    """
    Represents source and destination rule.
    """

    policy_name: str
    rules: list[SourceDestinationRule]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PolicySourceDestination":
        """Create an object from a given dict."""
        rules = data.pop("rules", [])
        return cls(
            policy_name=data.get("policy_name"),
            rules=[SourceDestinationRule.from_dict(rule) for rule in rules],
        )

    def update_from_args(self, args: dict[str, Any]) -> None:
        """Update an object from given user arguments."""
        if "policy_name" in args:
            self.policy_name = args["policy_name"]

        rule_name = args["rule_name"]
        rule = self.find_rule(rule_name)

        if not rule:
            raise DemistoException(f"Rule `{rule_name}` not found.")

        rule.update_from_args(args)

    def find_rule(self, rule_name: str) -> SourceDestinationRule | None:
        """Find a rule by name.

        Args:
            rule_name (str): The name of the rule.

        Returns:
            SourceDestinationRule | None: The rule if found, otherwise None.
        """
        for rule in self.rules:
            if rule.rule_name == rule_name:
                return rule

        return None



@dataclasses.dataclass
class PolicyExceptionRule:
    """
    Represents exception rule.
    """

    parent_policy_name: str
    parent_rule_name: str
    policy_type: str
    exception_rules: list[ExceptionRule]

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PolicyExceptionRule":
        """Create an object from a given dict."""
        exception_rules = data.pop("exception_rules", [])
        return cls(
            parent_policy_name=data.get("parent_policy_name"),
            parent_rule_name=data.get("parent_rule_name"),
            policy_type=data.get("policy_type"),
            exception_rules=[ExceptionRule.from_dict(exception_rule) for exception_rule in exception_rules],
        )

    def update_from_args(self, args: dict[str, Any]) -> None:
        """Update an object from given user arguments."""
        if "parent_policy_name" in args:
            self.parent_policy_name = args["parent_policy_name"]
        if "parent_rule_name" in args:
            self.parent_rule_name = args["parent_rule_name"]
        if "policy_type" in args:
            self.policy_type = args["policy_type"]

        exception_rule_name = args["exception_rule_name"]
        exception_rule = self.find_exception_rule(exception_rule_name)

        if exception_rule:
            exception_rule.update_from_args(args)
        else:
            self.exception_rules.append(ExceptionRule.from_args(args))


    def find_exception_rule(self, exception_rule_name: str) -> ExceptionRule | None:
        """Find an exception rule by name.

        Args:
            exception_rule_name (str): The name of the exception rule.

        Returns:
            ExceptionRule | None: The exception rule if found, otherwise None.
        """
        for exception_rule in self.exception_rules:
            if exception_rule.exception_rule_name == exception_rule_name:
                return exception_rule

        return None


def validate_authentication(func: Callable) -> Callable:
    """Decorator to ensure a valid access token is available before executing an API call.

    This decorator checks if the current access token stored in the integration context is valid.
    If it's missing or expired, it attempts to obtain a new one:
    - If a valid refresh token is available, it uses it to get a new access token.
    - If no valid refresh token is found, it performs a full authentication flow.

    Tokens and their expiry times are stored in the integration context, with a 10% buffer applied
    to expiration to account for timing edge cases (e.g., network delays).

    Args:
        func (Callable): The API function to wrap.

    Returns:
        Callable: A wrapped function that ensures valid authentication before executing.
    """

    @wraps(wrapped=func)
    def wrapper(client: "Client", *args, **kwargs):
        def is_token_expired(integration_context: dict[str, Any], key: str) -> bool:
            return datetime.now(timezone.utc) >= datetime.fromisoformat(integration_context[f"{key}_token_expiry_date"])

        def get_token_and_expiry_date(data: dict[str, Any], response_time: datetime, key: str) -> dict[str, Any]:
            expires_in = data[f"{key}_token_expires_in"]
            buffer = min(30, expires_in * 0.1)  # Edge case buffer for near-expiration edge-cases
            return {
                f"{key}_token": data[f"{key}_token"],
                f"{key}_token_expiry_date": (response_time + timedelta(seconds=expires_in - buffer)).isoformat(),
            }

        def set_tokens_in_integration_context(response: requests.Response, integration_context: dict[str, Any]) -> None:
            if "Date" in response.headers:
                response_time = parsedate_to_datetime(response.headers["Date"])
            else:
                response_time = datetime.now(timezone.utc)

            data = response.json()
            integration_context |= get_token_and_expiry_date(data, response_time, "access")

            if "refresh_token" in data:
                integration_context |= get_token_and_expiry_date(data, response_time, "refresh")

            set_integration_context(integration_context)

        def set_client_bearer_token(token: str) -> None:
            client._headers = {"Authorization": f"Bearer {token}"}

        integration_context = get_integration_context() or {}

        if "access_token" not in integration_context or is_token_expired(integration_context, "access"):
            if "refresh_token" not in integration_context or is_token_expired(integration_context, "refresh"):
                response = client.get_refresh_token()
            else:
                response = client.get_access_token(integration_context["refresh_token"])

            set_tokens_in_integration_context(response, integration_context)

        set_client_bearer_token(integration_context["access_token"])
        return func(client, *args, **kwargs)

    return wrapper


class Client(BaseClient):
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        verify: bool,
        proxy: bool,
        utc_now: datetime,
        api_limit=API_DEFAULT_LIMIT,
        **kwargs,
    ):
        self._username = username
        self._password = password
        self.api_limit = api_limit
        self.utc_now = utc_now
        super().__init__(
            base_url=urljoin(base_url, "dlp/rest/v1"),
            verify=verify,
            proxy=proxy,
        )

    def error_handler(self, res: requests.Response):
        """Error handler for the API response.

        Args:
            res (Response): Error response.

        Raises:
            DemistoException: There is no data to return.
        """
        if res.status_code == NO_CONTENT_CODE:
            raise DemistoException(
                NO_CONTENT_MESSAGE,
                res=res,
            )

        super()._handle_error(None, res, False)

    @validate_authentication
    def _http_request(self, *args, **kwargs):
        return super()._http_request(*args, **kwargs, error_handler=self.error_handler)

    def get_refresh_token(self) -> requests.Response:
        return super()._http_request(
            method="POST",
            url_suffix="auth/refresh-token",
            headers={"username": self._username, "password": self._password},
            resp_type="response",
        )

    def get_access_token(self, refresh_token: str) -> requests.Response:
        return super()._http_request(
            method="POST",
            url_suffix="auth/access-token",
            headers={"refresh-token": f"Bearer {refresh_token}"},
            resp_type="response",
        )

    def list_policies(self, policy_type: str = "DLP") -> dict:
        return self._http_request(
            method="GET",
            url_suffix="policy/enabled-names",
            params={"type": policy_type},
        )

    def list_policy_rules(self, policy_name: str) -> dict:
        return self._http_request(
            method="GET",
            url_suffix="policy/rules",
            params={"policyName": policy_name},
        )

    def list_exception_rules(self, policy_type: str = "DLP") -> dict:
        return self._http_request(
            method="GET",
            url_suffix="policy/rules/exceptions/all",
            params={"type": policy_type},
        )

    def get_exception_rule(
        self,
        policy_type: str,
        policy_name: str,
        rule_name: str,
    ) -> dict:
        return self._http_request(
            method="GET",
            url_suffix="policy/rules/exceptions",
            params={
                "type": policy_type,
                "policyName": policy_name,
                "ruleName": rule_name,
            },
        )

    def get_rule_severity_action(
        self,
        policy_name: str,
    ) -> dict:
        return self._http_request(
            method="GET",
            url_suffix="policy/rules/severity-action",
            params={"policyName": policy_name},
        )

    def get_rule_source_destination(
        self,
        policy_name: str,
    ) -> dict:
        return self._http_request(
            method="GET",
            url_suffix="policy/rules/source-destination",
            params={"policyName": policy_name},
        )

    def list_incidents(
        self,
        incident_type: str = "INCIDENTS",
        ids: list[int] | None = None,
        sort_by: str | None = None,
        from_date: str | None = None,
        to_date: str | None = None,
        detected_by: str | None = None,
        analyzed_by: str | None = None,
        event_id: str | None = None,
        destination: str | None = None,
        policies: list[str] | None = None,
        action: str | None = None,
        source: str | None = None,
        status: str | None = None,
        severity: str | None = None,
        endpoint_type: str | None = None,
        channel: str | None = None,
        assigned_to: str | None = None,
        tag: str | None = None,
        remove_ignored_incidents: bool | None = None,
    ) -> dict:
        """
        Retrieve incidents based on the provided filters or by incident IDs.

        Args:
            incident_type (str): The type of incidents to retrieve. Valid values: INCIDENTS, DISCOVERY.
            ids (list[int] | None): Comma-separated list of incident IDs. Overrides all filters if provided.
            sort_by (str | None): Field to sort by. Valid value: INSERT_DATE.
            from_date (str | None): Start date for filtering incidents (dd/MM/yyyy HH:mm:ss).
            to_date (str | None): End date for filtering incidents (dd/MM/yyyy HH:mm:ss).
            detected_by (str | None): Agent that detected the incident.
            analyzed_by (str | None): Policy engine ID.
            event_id (str | None): Event ID number.
            destination (str | None): Destination associated with the incident.
            policies (list[str] | None): Policies that triggered the incidents.
            action (str | None): Action taken on the incident.
            source (str | None): Source associated with the incident.
            status (str | None): Status of the incident.
            severity (str | None): Severity level of the incident.
            endpoint_type (str | None): Endpoint type.
            channel (str | None): Channel associated with the incident.
            assigned_to (str | None): Administrator assigned to the incident.
            tag (str | None): Incident tag.
            remove_ignored_incidents (bool): Filter out ignored incidents (default is False).

        Returns:
            dict: API response with the retrieved incidents.
        """
        if ids:
            json_data = {"type": incident_type, "ids": ids}
        else:
            json_data = remove_empty_elements(
                {
                    "type": incident_type,
                    "sort_by": sort_by,
                    "from_date": from_date,
                    "to_date": to_date,
                    "detected_by": detected_by,
                    "analyzed_by": analyzed_by,
                    "event_id": event_id,
                    "destination": destination,
                    "policies": policies,
                    "action": action,
                    "source": source,
                    "status": status,
                    "severity": severity,
                    "endpoint_type": endpoint_type,
                    "channel": channel,
                    "assigned_to": assigned_to,
                    "tag": tag,
                    "remove_ignored_incidents": remove_ignored_incidents,
                }
            )

        return self._http_request(
            method="POST",
            url_suffix="incidents",
            json_data=json_data,
        )

    def update_rule(
        self,
        rule: dict,
    ) -> dict:
        return self._http_request(
            method="POST",
            url_suffix="policy/rules",
            json_data=remove_empty_elements(rule),
            resp_type="response",
        )

    def update_rule_severity_action(
        self,
        severity_action_rule: dict,
    ) -> dict:
        return self._http_request(
            method="POST",
            url_suffix="policy/rules/severity-action",
            json_data=remove_empty_elements(severity_action_rule),
            resp_type="response",
        )

    def update_rule_source_destination(
        self,
        source_destination_rule: dict,
    ) -> dict:
        return self._http_request(
            method="POST",
            url_suffix="policy/rules/source-destination",
            json_data=remove_empty_elements(source_destination_rule),
            resp_type="response",
        )

    def update_incidents(
        self,
        event_ids: list[str],
        incident_type: str,
        action_type: str,
        value: str,
        comment: str | None = None,
        scan_partitions: str | None = None,
    ) -> dict:
        """
        Update incidents based on specified parameters.

        Args:
            type (str): The type of incidents to update (e.g., INCIDENTS, DISCOVERY).
            action_type (str): The type of action to perform (e.g., STATUS, SEVERITY, ASSIGN_TO, etc.).
            value (str): The value associated with the action type.
            comment (str | None): A comment to attach to the incidents (required for ADD_COMMENT).
            scan_partitions (str | None): Parameter to identify if partition_index is provided (e.g., ALL, NONE, LAST_ACTIVE).
            event_ids (list[str] | None): List of event IDs to update incidents.
            incident_keys (list[dict] | None): List of incident keys to update incidents.

        Returns:
            dict: Response from the update incidents API.
        """
        payload = remove_empty_elements(
            {
                "type": incident_type,
                "action_type": action_type,
                "value": value,
                "comment": comment,
                "scan_partitions": scan_partitions,
                "event_ids": event_ids,
            }
        )
        demisto.debug(f"update incident request with {payload=}")
        return self._http_request(
            method="POST",
            url_suffix="incidents/update",
            json_data=payload,
            resp_type="response",
        )

    def update_exception_rule(
        self,
        parent_policy_name: str,
        exception_rule: dict,
    ) -> dict:
        """
        Sends a request to create an exception rule in a specified policy and rule.

        Args:
            See arguments from the create_exception_rule_command.

        Returns:
            dict: Response from the server.
        """

        return self._http_request(
            method="POST",
            url_suffix="policy/rules/exceptions",
            params={"policyName": parent_policy_name},
            json_data=remove_empty_elements(exception_rule),
            resp_type="response",
        )


""" COMMAND FUNCTIONS """


def get_events_command(
    client: Client,
    args: dict[str, Any],
) -> tuple[CommandResults, List[dict[str, Any]]]:
    limit: int = arg_to_number(args.get("limit")) or DEFAULT_MAX_FETCH
    since_time = arg_to_datetime(args.get("since_time"), settings=DATEPARSER_SETTINGS)
    events, _, _ = fetch_events_command_sub(client, limit, datetime.utcnow(), since_time)

    result = CommandResults(
        readable_output=tableToMarkdown("Incidents", events),
        raw_response=events,
    )
    return result, events


def fetch_events_command_sub(
    client: Client,
    max_fetch: int,
    to_time: datetime,
    last_fetch_time: datetime,
    last_run_ids: list[int] | None = None,
) -> tuple[list[dict[str, Any]], list[int], str]:
    """
    Fetches Forcepoint DLP incidents as events to XSIAM.
    Note: each report of incident will be considered as an event.
    """
    from_time = last_fetch_time
    events = []
    last_run_ids = set(last_run_ids or set())
    new_last_run_ids: dict[str, set] = defaultdict(set)
    incidents_response = client.list_incidents(
        from_date=to_str_time(from_time), to_date=to_str_time(to_time)
    )
    incidents = incidents_response.get("incidents", [])
    for incident in incidents:
        if incident["id"] not in last_run_ids:
            incident["_collector_source"] = "API"
            events.append(incident)
            new_last_run_ids[incident["event_time"]].add(incident["id"])
            if len(events) == max_fetch:
                break

    if not events and incidents:
        # Anti-starvation protection, we've exhausted all events for this second, but they're all duplicated.
        # This means that we've more events in the minimal epoch, that we're able to get in a single fetch,
        # and we'll ignore any additional events in this particular second.
        next_fetch_time: str = to_str_time(from_time + timedelta(seconds=1))
        demisto.info(
            f"Moving the fetch to the next second:{next_fetch_time}. Any additional events in this "
            f"second will be lost!"
        )
        return [], [], next_fetch_time

    # We've got events for this time span, so start from that to_time in the next fetch,
    # otherwise use the to_time - 1 second (as we might have more events for this second)
    next_fetch_time = (
        events[-1]["event_time"] if events else to_str_time(to_time - timedelta(seconds=1))
    )

    return events, list(new_last_run_ids[next_fetch_time]), next_fetch_time


def test_module(client: Client) -> str:
    """
    Test module.

    Args:
        client (Client): Forcepoint DLP client.
    Raises:
        DemistoException: Unexpected error.

    Returns:
        str: Output message.
    """
    try:
        client.list_policies()
    except DemistoException as err:
        if err.res is not None and err.res.status_code == http.HTTPStatus.FORBIDDEN:
            return "Authorization Error: invalid credentials."

        raise err

    return "ok"


def fetch_events(client, max_fetch):
    events = []
    forward = demisto.getLastRun().get("forward") or {
        "last_fetch": to_str_time(datetime.utcnow() + timedelta(seconds=1)),
        "last_events_ids": [],
    }

    from_time = from_str_time(forward["last_fetch"])
    to_time = client.utc_now
    demisto.info(f"looking for backward events from:{from_time} to:{to_time}")
    forward_events, last_events_ids, next_fetch_time = fetch_events_command_sub(
        client, max_fetch, to_time, from_time, forward["last_events_ids"]
    )
    forward = {
        "last_fetch": next_fetch_time,
        "last_events_ids": last_events_ids,
    }
    events.extend(forward_events)

    send_events_to_xsiam(events, VENDOR, PRODUCT)  # noqa
    demisto.setLastRun(
        {
            "forward": forward,
        }
    )


def list_policy_command(client: Client, args: dict) -> CommandResults:
    """
    List the names of all enabled policies displayed in the 'Manage DLP and Discovery Policies' section.

    Args:
        client (Client): Forcepoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Outputs for XSOAR.
    """

    policy_type = args.get("type")
    all_results = argToBoolean(args.get("all_results", False))
    limit = arg_to_number(args.get("limit")) or 50

    response = client.list_policies(policy_type=policy_type)
    results = get_paginated_data(
        response.get("enabled_policies", []),
        limit,
        all_results,
    )

    outputs = [{"name": policy} for policy in results]

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.Policy",
        outputs_key_field="name",
        outputs=outputs,
        readable_output=tableToMarkdown(
            name="Policies List:",
            t=outputs,
            headers=["name"],
            removeNull=True,
            headerTransform=string_to_table_header,
        ),
    )


def list_policy_rule_command(client: Client, args: dict) -> list[CommandResults]:
    """
    List the details of policy rules and classifiers, including condition properties.

    Args:
        client (Client): ForcePoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Command results to return to the war room.
    """
    policy_name = args.get("policy_name")
    all_results = argToBoolean(args.get("all_results", False))
    limit = arg_to_number(args.get("limit")) or 50

    response = client.list_policy_rules(policy_name=policy_name)
    rules = get_paginated_data(
        response.get("rules", []),
        limit,
        all_results,
    )

    description = response.get("description")
    policy_level = dict_safe_get(response, ["policy_level", "level"])

    outputs = {
        "dlp_version": response.get("dlp_version"),
        "policy_name": response.get("policy_name"),
        "enabled": response.get("enabled"),
        "predefined_policy": response.get("predefined_policy"),
        "description": description,
        "policy_level": policy_level,
        "policy_level_data_type": dict_safe_get(response, ["policy_level", "data_type"]),
        "Rule": [
            {
                "rule_name": rule.get("rule_name"),
                "enabled": rule.get("enabled"),
                "parts_count_type": rule.get("parts_count_type"),
                "condition_relation_type": rule.get("condition_relation_type"),
                "Classifier": rule.get("classifiers", []),
            }
            for rule in rules
        ],
    }
    outputs = remove_empty_elements(outputs)

    readable_output = tableToMarkdown(
        f"Policy `{policy_name}` Rule List:\nDescription: {description}\nPolicy level: {policy_level}\n",
        outputs.get("Rule", []),
        headers=[
            "rule_name",
            "enabled",
            "parts_count_type",
            "condition_relation_type",
        ],
        removeNull=True,
        headerTransform=string_to_table_header,
    )

    command_results = [
        CommandResults(
            readable_output=readable_output,
            outputs_prefix=f"{INTEGRATION_PREFIX}.Policy",
            outputs_key_field="policy_name",
            raw_response=response,
            outputs=outputs,
        )
    ]

    for rule in outputs.get("Rule", []):
        for clsf in rule.get("Classifier", []):
            rule_name = rule.get("rule_name")
            clsf_name = clsf.get("classifier_name")
            readable_output = tableToMarkdown(
                f"Rule `{rule_name}` Classifier `{clsf_name}`:",
                clsf,
                headers=CLASSIFIER_HEADERS,
                removeNull=True,
                headerTransform=string_to_table_header,
            )

            command_results.append(
                CommandResults(
                    readable_output=readable_output,
                )
            )
    return command_results


def list_exception_rule_command(client: Client, args: dict) -> CommandResults:
    """
    List all exception rules associated with policies, including detailed information about conditions and classifiers.

    Args:
        client (Client): ForcePoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Outputs for XSOAR.
    """
    policy_type = args.get("policy_type", "DLP")  # Defaults to "DLP" if not provided

    if policy_name := args.get("policy_name"):
        if not (rule_name := args.get("rule_name")):
            raise DemistoException(MISSING_RULE_NAME)

        response = client.get_exception_rule(
            policy_type=policy_type,
            policy_name=policy_name,
            rule_name=rule_name,
        )

        outputs = transform_keys(
            response,
            {
                "classifier_details": "Classifier",
                "classifiers": "Classifier",
                "exception_rules": "RuleException",
            },
        )
        readable_output = tableToMarkdown(
            f"Policy `{policy_name}` \nRule: `{rule_name}` exceptions:",
            outputs.get("RuleException", []),
            headers=RULE_EXCEPTION_HEADERS,
            removeNull=True,
            headerTransform=string_to_table_header,
        )
    else:
        response = client.list_exception_rules(policy_type=policy_type)

        outputs = get_paginated_data(
            data=response.get("exception_rules", []),
            limit=arg_to_number(args.get("limit")) or DEFAULT_LIMIT,
            all_results=argToBoolean(args.get("all_results", False)),
        )

        readable_output = tableToMarkdown(
            name="Exception Rules List:",
            t=outputs,
            headers=["policy_name", "rule_name", "exception_rule_names"],
            removeNull=True,
            headerTransform=string_to_table_header,
        )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.PolicyException",
        outputs_key_field="policy_name",
        outputs=outputs,
        readable_output=readable_output,
        raw_response=response,
    )


def get_rule_severity_action_command(client: Client, args: dict) -> list[CommandResults]:
    """
    Retrieve details of rule severity and corresponding action properties for a specified policy.

    Args:
        client (Client): ForcePoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Command results to return to the war room.
    """
    policy_name = args.get("policy_name")

    response = client.get_rule_severity_action(policy_name=policy_name)
    outputs = transform_keys(
        response,
        {
            "classifier_details": "ClassifierDetail",
            "rules": "Rule",
        },
    )

    command_results = []

    for rule in outputs.get("Rule", []):
        rule_name = rule.get("rule_name")
        max_matches = rule.get("max_matches")
        readable_output = tableToMarkdown(
            f"Policy `{policy_name}` Rule `{rule_name}` Severity and Actions:\nMax matches: {max_matches}",
            rule.get("ClassifierDetail", []),
            headers=[
                "number_of_matches",
                "selected",
                "action_plan",
            ],
            removeNull=True,
            headerTransform=string_to_table_header,
        )
        command_results.append(
            CommandResults(
                outputs=outputs,
                outputs_prefix=f"{INTEGRATION_PREFIX}.SeverityActionRule",
                outputs_key_field="policy_name",
                readable_output=readable_output,
                raw_response=response,
            )
        )

    return command_results


def get_rule_source_destination_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieve the source and destination details of rules associated with a specified policy.

    Args:
        client (Client): ForcePoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Command results to return to the war room.
    """
    policy_name = args.get("policy_name")
    response = client.get_rule_source_destination(policy_name=policy_name)

    outputs = transform_keys(
        response,
        {
            "rules": "Rule",
            "rule_source": "Source",
            "rule_destination": "Destination",
            "channels": "Channel",
        },
    )
    hr = [
        rule
        | {
            "source_endpoint_channel_machine_type": dict_safe_get(
                rule, ["Source", "endpoint_channel_machine_type"]
            ),
            "source_endpoint_connection_type": dict_safe_get(
                rule, ["Source", "endpoint_connection_type"]
            ),
            "destination_email_monitor_directions": dict_safe_get(
                rule, ["Destination", "email_monitor_directions"]
            ),
        }
        for rule in outputs.get("Rule", []) or []
    ]

    return CommandResults(
        outputs=outputs,
        outputs_prefix=f"{INTEGRATION_PREFIX}.SourceDestinationRule",
        outputs_key_field="policy_name",
        readable_output=tableToMarkdown(
            f"Policy `{policy_name}` Source and Destination Rules Details:",
            hr,
            headers=[
                "rule_name",
                "source_endpoint_channel_machine_type",
                "source_endpoint_connection_type",
                "destination_email_monitor_directions",
            ],
            removeNull=True,
            headerTransform=string_to_table_header,
        ),
        raw_response=response,
    )


def list_incidents_command(client: Client, args: dict) -> CommandResults:
    """
    Retrieve a list of incidents based on specified filters.

    Args:
        client (Client): The ForcePoint DLP client instance.
        args (dict): Command arguments.

    Returns:
        CommandResults: Results to return to the war room.
    """
    incident_type = args.get("type", "INCIDENTS")
    from_date = arg_to_datetime(args.get("from_date"), required=True)
    to_date = arg_to_datetime(args.get("to_date", "now"), required=True)
    status = args.get("status")
    ids = argToList(args.get("ids"))

    incidents_response = client.list_incidents(
        incident_type=incident_type,
        ids=ids,
        from_date=from_date.strftime(DATE_FORMAT),
        to_date=to_date.strftime(DATE_FORMAT),
        status=status,
    )

    incidents = incidents_response.get("incidents", [])
    incidents = get_paginated_data(
        incidents,
        arg_to_number(args.get("limit")) or 50,
        argToBoolean(args.get("all_results", False)),
    )

    return CommandResults(
        outputs_prefix=f"{INTEGRATION_PREFIX}.Incident",
        outputs_key_field="id",
        outputs=incidents,
        readable_output=tableToMarkdown(
            name="Incidents List:",
            t=incidents,
            headers=INCIDENT_HEADERS,
            removeNull=True,
            headerTransform=string_to_table_header,
        ),
    )


def create_rule_command(client: Client, args: dict) -> CommandResults:
    """
    Create a new rule in a specified DLP policy with a single classifier.
    If the specified policy does not exist, it will be created automatically.

    Args:
        client (Client): ForcePoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Command results to return to the war room.
    """
    policy_name = args.get("policy_name")
    rule_name = args.get("rule_name")

    enabled_policies = client.list_policies().get("enabled_policies", [])

    if policy_name in enabled_policies:
        policy = client.list_policy_rules(policy_name)
        rule = find_rule(policy, rule_name)

        if rule:
            raise DemistoException("The rule is already exist. Use the update command.")
    else:
        policy = None

    if entry_id := args.get("entry_id"):
        rule = read_entry_id(entry_id)
    elif policy:
        rule = PolicyRule.from_dict(policy)
        rule.update_from_args(args)
        rule = dataclasses.asdict(rule)
    else:
        rule = PolicyRule.from_args(args)
        rule = dataclasses.asdict(rule)

    client.update_rule(rule)
    return CommandResults(
        readable_output=f"Rule `{rule_name}` was successfully created in policy '{policy_name}'.",
    )


def update_rule_command(client: Client, args: dict) -> CommandResults:
    """
    Update an existing rule in a specific DLP policy or create a classifier within it.

    Args:
        client (Client): ForcePoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Command results to return to the war room.
    """
    policy_name = args.get("policy_name")
    rule_name = args.get("rule_name")

    enabled_policies = client.list_policies().get("enabled_policies", [])

    if policy_name not in enabled_policies:
        raise DemistoException("The policy does not exist. Use the create command.")

    policy = client.list_policy_rules(policy_name)
    rule = find_rule(policy, rule_name)

    if not rule:
        raise DemistoException("The rule does not exist. Use the create command.")

    if entry_id := args.get("entry_id"):
        rule = read_entry_id(entry_id)
    elif policy:
        rule = PolicyRule.from_dict(policy)
        rule.update_from_args(args)
        rule = dataclasses.asdict(rule)
    else:
        rule = PolicyRule.from_args(args)
        rule = dataclasses.asdict(rule)

    client.update_rule(rule)
    return CommandResults(
        readable_output=f"Rule `{rule_name}` was successfully updated in policy '{policy_name}'.",
    )


def update_rule_severity_action_command(client: Client, args: dict) -> CommandResults:
    """
    Update the severity actions for a rule in a specific DLP policy.

    Args:
        client (Client): ForcePoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Command results to return to the war room.
    """
    policy_name = args.get("policy_name")
    rule_name = args.get("rule_name")

    policy = client.get_rule_severity_action(policy_name)
    rule = find_rule(policy, rule_name)

    if not rule:
        raise DemistoException(f"Rule `{rule_name}` not found.")

    if entry_id := args.get("entry_id"):
        severity_action = read_entry_id(entry_id)
    else:
        severity_action = PolicySeverityAction.from_dict(policy)
        severity_action.update_from_args(args)
        severity_action = dataclasses.asdict(severity_action)

    client.update_rule_severity_action(severity_action)
    return CommandResults(
        readable_output=f"Severity actions for Rule `{rule_name}` in policy '{policy_name}' was successfully updated.",
    )


def update_rule_source_destination_command(client: Client, args: dict) -> CommandResults:
    """
    Update the source and destination settings for a rule in a specific DLP policy.

    Args:
        client (Client): ForcePoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Command results to return to the war room.
    """
    policy_name = args.get("policy_name")
    rule_name = args.get("rule_name")

    policy = client.get_rule_source_destination(policy_name)
    rule = find_rule(policy, rule_name)

    if not rule:
        raise DemistoException("The rule not found.")

    if entry_id := args.get("entry_id"):
        source_destination = read_entry_id(entry_id)
    else:
        source_destination = PolicySourceDestination.from_dict(policy)
        source_destination.update_from_args(args)
        source_destination = dataclasses.asdict(source_destination)

    client.update_rule_source_destination(source_destination)
    return CommandResults(
        readable_output=(
            f"Source and destination for Rule `{rule_name}` in policy '{policy_name}' was successfully updated."
        )
    )


def create_exception_rule_command(client: Client, args: dict) -> CommandResults:
    """
    Create an exception rule for a specified parent rule and policy type.

    Args:
        client (Client): ForcePoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Command results to return to the war room.
    """
    parent_policy_name = args.get("parent_policy_name")
    parent_rule_name = args.get("parent_rule_name")
    policy_type = args.get("policy_type")
    exception_rule_name = args.get("exception_rule_name")

    exception_rules_policy = client.get_exception_rule(
        policy_type=policy_type,
        policy_name=parent_policy_name,
        rule_name=parent_rule_name,
    )
    enabled_policies = client.list_policies().get("enabled_policies", [])

    if parent_policy_name in enabled_policies:
        exception_rules = exception_rules_policy.get("exception_rules", [])
        exception_rule = find_exception_rule(exception_rules, exception_rule_name)

        if exception_rule:
            raise DemistoException("The exception rule already exists. Use the update command.")

    if entry_id := args.get("entry_id"):
        exceptions_policy = read_entry_id(entry_id)
    else:
        exceptions_policy = PolicyExceptionRule.from_dict(exception_rules_policy)
        exceptions_policy.update_from_args(args)
        exceptions_policy = dataclasses.asdict(exceptions_policy)

    client.update_exception_rule(parent_policy_name, exceptions_policy)
    return CommandResults(
        readable_output=f"Exception rule '{exception_rule_name}' was successfully created in rule "
        f"'{parent_rule_name}' under policy '{parent_policy_name}'.",
    )


def update_exception_rule_command(client: Client, args: dict) -> CommandResults:
    """
    Update an existing exception rule for a specified parent rule and policy type.

    Args:
        client (Client): ForcePoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Command results to return to the war room.
    """
    parent_policy_name = args.get("parent_policy_name")
    parent_rule_name = args.get("parent_rule_name")
    policy_type = args.get("policy_type")
    exception_rule_name = args.get("exception_rule_name")

    exception_rules_policy = client.get_exception_rule(
        policy_type=policy_type,
        policy_name=parent_policy_name,
        rule_name=parent_rule_name,
    )
    enabled_policies = client.list_policies().get("enabled_policies", [])

    if parent_policy_name in enabled_policies:
        exception_rules = exception_rules_policy.get("exception_rules", [])
        exception_rule = find_exception_rule(exception_rules, exception_rule_name)

        if exception_rule is None:
            raise DemistoException("The exception rule does not exist. Use the create command.")

    if entry_id := args.get("entry_id"):
        exceptions_policy = read_entry_id(entry_id)
    else:
        exceptions_policy = PolicyExceptionRule.from_dict(exception_rules_policy)
        exceptions_policy.update_from_args(args)
        exceptions_policy = dataclasses.asdict(exceptions_policy)

    client.update_exception_rule(parent_policy_name, exceptions_policy)
    return CommandResults(
        readable_output=f"Exception rule '{exception_rule_name}' was successfully updated in rule "
        f"'{parent_rule_name}' under policy '{parent_policy_name}'.",
    )


def update_incident_command(client: Client, args: dict) -> CommandResults:
    """
    Update an incident's attributes such as status, severity, assignment, comments, tags, release flag,
    or false positive indication.

    Args:
        client (Client): ForcePoint DLP client.
        args (dict): Command arguments.

    Returns:
        CommandResults: Command results to return to the war room.
    """
    ids = argToList(args.get("event_ids"))
    incident_type = args.get("type")
    comment = args.get("comment")

    for arg_key, action_type in INCIDENT_UPDATE_MAPPER:
        value = args.get(arg_key)
        if arg_key == "false_positive" and value:
            value = 1 if argToBoolean(value) else 0

        if value:
            client.update_incidents(
                event_ids=ids,
                incident_type=incident_type,
                action_type=action_type,
                value=value,
                comment=comment,
            )

    return CommandResults(
        readable_output="Incidents was successfully updated.",
    )


def fetch_incidents(
    client: Client,
    last_run: dict[str, Any],
    first_fetch: datetime,
    max_fetch: int,
    mirror_direction: str | None,
) -> tuple[list[dict], dict[str, Any]]:
    """
    Fetch Forcepoint DLP incidents.
    The incident endpoint doesn't supports pagination we manage it in the code.
    The incident endpoint has sort body parameter that now works, we sort the response in the code.
    The incident endpoint doesn't supports offset, we use the start time and when needed, add 1 second.

    Args:
        client (Client): ForcePoint DLP client.
        last_run (dict[str, Any]): Holds the last fetch time and the seen incident IDs in that time.
        first_fetch (datetime): If last_run is None then fetch all incidents since first_fetch.
        max_fetch (int): Maximum numbers of incidents per fetch.
        mirror_direction (str | None): Whether the incident is incoming, outgoing or both.

    Returns:
        tuple[list[dict], dict[str, Any]]: Incidents and the next fetch metadata.
    """
    demisto.debug(f"fetch: {last_run=}")
    last_fetch: datetime | None = arg_to_datetime(last_run.get("last_fetch"))
    last_ids = set(last_run.get("last_ids", []))

    start_date = last_fetch or first_fetch
    start_time = start_date.strftime(DATE_FORMAT)
    end_time = datetime.now().strftime(DATE_FORMAT)

    demisto.debug(f"fetch: start time: {start_time} end time: {end_time}.")

    response = client.list_incidents(
        incident_type="INCIDENTS",
        sort_by="INSERT_DATE",
        from_date=start_time,
        to_date=end_time,
    )

    data = response.get("incidents") or []
    fetch_count = len(data)

    if last_ids:
        # filter out IDs with a lower value than last_id as the they are sorted in ascending order.
        data = [item for item in data if item["id"] not in last_ids]
        demisto.debug(f"fetch: {len(data)} new incidents were detected in {fetch_count} fetched incidents.")

    if not data:
        if fetch_count == API_DEFAULT_LIMIT:
            # API limit reached for the given time-frame, update the start time by 1 second and attempt a new fetch.
            demisto.debug(f"fetch: API limit capped out for incident time '{start_time}'.")
            start_date += timedelta(seconds=1)
            start_time = start_date.strftime(DATE_FORMAT)

            demisto.debug(f"fetch: Re-fetching with new start time: '{start_time}'.")
            response = client.list_incidents(
                incident_type="INCIDENTS",
                sort_by="INSERT_DATE",
                from_date=start_time,
                to_date=end_time,
            )
            data = response.get("incidents")

            # Update last_run to avoid previous step.
            last_run["last_fetch"] = start_time
            last_run["last_ids"] = []

        if not data:
            # Early exit incase no new incidents were found.
            demisto.debug("fetch: 0 incidents were fetched, exiting...")
            return last_run, []

    data.sort(key=lambda item: datetime.strptime(item["incident_time"], DATE_FORMAT))
    data = data[:max_fetch]

    integration_context = get_integration_context()
    if "first_incident_time" not in integration_context:
        # Update the first incident time if it doesn't not exists.
        integration_context["first_incident_time"] = data[0]["incident_time"]
        set_integration_context(integration_context)

    last_run["last_fetch"] = data[-1]["incident_time"]
    last_run["last_ids"] = set()
    mirror_data = {"mirror_direction": mirror_direction, "mirror_instance": demisto.integrationInstance()}
    incidents = []

    for item in data:
        if item["incident_time"] == last_run["last_fetch"]:
            last_run["last_ids"].add(item["id"])

        item |= mirror_data
        incidents.append(
        {
                "name": f"Forcepoint DLP Incident - {item['id']}",
                "occurred": arg_to_datetime(item["incident_time"], required=True).strftime(XSOAR_DATE_FORMAT),
                "severity": FP_XSOAR_SEVERITY_MAPPER.get(item.get("severity", "LOW")),
                "dbotMirrorId": f"{item['event_id']}-{item['id']}",
                "rawJSON": json.dumps(item),
                **mirror_data,
        }
    )

    last_run["last_ids"] = list(last_run["last_ids"])

    if len(last_run["last_ids"]) == API_DEFAULT_LIMIT:
        # API limit reached for the given time-frame, update the last fetch time by 1 second and empty last IDs.
        demisto.debug(f"fetch: API limit capped out for incident time '{start_time}'.")
        start_date += timedelta(seconds=1)
        last_run["last_fetch"] = start_date.strftime(DATE_FORMAT)
        last_run["last_ids"] = []

    return last_run, incidents


def get_mapping_fields_command() -> GetMappingFieldsResponse:
    """
    Pulls the remote schema for the different incident types, and their associated incident fields,
    from the remote system.

    Returns:
        GetMappingFieldsResponse: Dictionary with keys as field names.
    """
    demisto.debug("Get Forcepoint DLP mapping fields")
    mapping_response = GetMappingFieldsResponse()

    incident_type_scheme = SchemeTypeMapping(type_name="Forcepoint Incident")
    for mirror_field in MIRRORING_FIELDS:
        incident_type_scheme.add_field(name=mirror_field)

    mapping_response.add_scheme_type(incident_type_scheme)

    return mapping_response


def update_remote_system(
    client: Client,
    args: dict[str, Any],
) -> str:
    """
    This command pushes local changes to the remote system.
    Args:
        client: XSOAR Client to use.
        args:
            args['data']: the data to send to the remote system.
            args['entries']: the entries to send to the remote system.
            args['incident_changed']: boolean telling us if the local incident indeed changed or not.
            args['remote_incident_id']: the remote incident id.
    Returns: The remote incident id - ticket_id
    """
    demisto.debug("update_remote_system")
    parsed_args = UpdateRemoteSystemArgs(args)

    incident_id = parsed_args.remote_incident_id

    demisto.debug(
        f"Got the following delta keys {str(list(parsed_args.delta))}"
        if parsed_args.delta
        else "There is no delta fields in Forcepoint DLP"
    )

    if parsed_args.incident_changed:
        demisto.debug(f"Incident changed: {parsed_args.incident_changed}, {parsed_args.delta=}")

        update_args = parsed_args.delta
        updated_arguments = {}

        for changed_key, changed_value in update_args.items():
            if isinstance(changed_value, bool):
                changed_value = str(1 if changed_value else 0)

            if changed_key == "severity":
                changed_value = XSOAR_FP_SEVERITY_MAPPER.get(changed_value, 1)

            demisto.debug(f"{changed_key=}")
            if changed_key in MIRRORING_FIELDS:
                updated_arguments[changed_key] = changed_value
                client.update_incidents(
                    event_ids=[incident_id.split("-")[0]],
                    incident_type="INCIDENTS",
                    action_type=changed_key.upper(),
                    value=(
                        changed_value.upper() if isinstance(changed_value, str) else changed_value
                    ),
                )
                demisto.debug(
                    f"Updating [{changed_key}] -> {changed_value} to incident {incident_id} Forcepoint DLP.\
                          {updated_arguments=}|| {update_args=}"
                )
            elif changed_key == "closingUserId":
                demisto.debug("closing incident")
                client.update_incidents(
                    event_ids=[incident_id.split("-")[0]],
                    incident_type="INCIDENTS",
                    action_type="STATUS",
                    value="CLOSE",
                )
                demisto.debug(
                    f"Updating [STATUS] -> CLOSE to incident {incident_id} Forcepoint DLP.\
                          {updated_arguments=}|| {update_args=}"
                )

    demisto.info(f"Remote data of {incident_id}: {parsed_args.data}")

    return incident_id


def get_remote_data_command(
    client: Client,
    args: dict[str, Any],
) -> GetRemoteDataResponse:
    """
    Gets new information about the incidents in the remote system
    and updates existing incidents in Cortex XSOAR.
    Args:
        client: Forcepoint DLP API client.
        args (Dict[str, Any]): command arguments.
    Returns:
        GetRemoteDataResponse: first entry is the incident (which can be completely empty) and the new entries.
    """
    parsed_args = GetRemoteDataArgs(args)

    incident_id = parsed_args.remote_incident_id.split("-")[1]

    last_update = parsed_args.last_update

    demisto.debug(f"Check {incident_id} update from {last_update}")

    response = client.list_incidents(
        ids=[incident_id],
    )
    incidents = response.get("incidents", [])
    entries = []

    if not incidents:
        return GetRemoteDataResponse({}, [])

    mirrored_ticket: dict[str, Any] = incidents[0]
    ticket_last_update = mirrored_ticket.get("incident_time")

    demisto.debug(f"Incident {incident_id} - {ticket_last_update=} {last_update=}")

    if mirrored_ticket.get("status") == "Closed":
        entries.append(
            {
                "Type": EntryType.NOTE,
                "Contents": {
                    "dbotIncidentClose": True,
                    "closeReason": "Closed from Forcepoint DLP.",
                },
                "ContentsFormat": EntryFormat.JSON,
            }
        )

    return GetRemoteDataResponse(mirrored_ticket, entries)


def get_modified_remote_data_command(
    client: Client,
    args: dict[str, Any],
):
    """
    Queries for incidents that were modified since the last update.

    Args:
        client: Forcepoint DLP client.
        args (Dict[str, Any]): command arguments.

    Returns:
        GetModifiedRemoteDataResponse: modified tickets from Cyberint.
    """
    remote_args = GetModifiedRemoteDataArgs(args)
    last_update_time = arg_to_datetime(remote_args.last_update)
    modified_incident_ids = []

    integration_context = get_integration_context()
    first_incident_time = integration_context.get("first_incident_time")
    from_date = first_incident_time

    demisto.debug(f"get_modified_remote_data_command: {last_update_time=}.")
    demisto.debug(f"get_modified_remote_data_command: {first_incident_time=}.")

    if not from_date:
        demisto.debug("get_modified_remote_data_command: first incident time not found")
        return GetModifiedRemoteDataResponse([])

    end_time = datetime.now().strftime(DATE_FORMAT)
    demisto.debug(
        f"get_modified_remote_data_command: start time: {from_date} end time: {end_time}."
    )

    response = client.list_incidents(
        incident_type="INCIDENTS",
        sort_by="INSERT_DATE",
        from_date=from_date,
        to_date=end_time,
    )

    incidents = response.get("incidents", [])

    demisto.debug(
        f"get_modified_remote_data_command: got: {len(incidents)} incidents,\
              start to filter for the updated after {last_update_time}."
    )

    for incident in incidents:
        history = incident.get("history", [])
        if history:
            update_time = arg_to_datetime(history[0]["update_time"])
            demisto.debug(
                f"get_modified_remote_data_command: got: {update_time=} > {last_update_time=}."
            )
            if update_time and last_update_time:
                update_time = update_time.replace(tzinfo=None)
                last_update_time = last_update_time.replace(tzinfo=None)

            if (update_time and last_update_time and update_time > last_update_time) or (
                not last_update_time
            ):
                event_id = incident["event_id"]
                incident_id = incident["id"]
                modified_incident_ids.append(f"{event_id}-{incident_id}")

    demisto.debug(
        f"get_modified_remote_data_command: got: {len(modified_incident_ids)} updated incidents."
    )

    return GetModifiedRemoteDataResponse(modified_incident_ids)


""" HELPER FUNCTIONS """


def get_paginated_data(data: list, limit: int, all_results: bool):
    return data if all_results else data[:limit]


def transform_keys(data: DictOrList, key_map: dict[str, str] | None = None) -> DictOrList:
    """Recursively transforms the keys of a dictionary or list of dictionaries
        according to a provided key_map. If a key is not found in the key_map,
        it can be camelized based on the value's type.

    Args:
        data (DictOrList): A dictionary or list of dictionaries to transform.
        key_map (dict[str, str] | None): A mapping of old key names to new key names.
            Defaults to None.

    Returns:
        DictOrList: The transformed structure with updated keys.
    """
    if key_map is None:
        key_map = {}

    if isinstance(data, list):
        return [transform_keys(item, key_map) for item in data]

    if isinstance(data, dict):
        return {
            key_map.get(
                key,
                (
                    camelize_string(key)
                    if isinstance(value, dict)
                    or (value and isinstance(value, list) and isinstance(value[0], dict))
                    else key
                ),
            ): (transform_keys(value, key_map) if isinstance(value, (dict, list)) else value)
            for key, value in data.items()
        }

    return data


def read_entry_id(entry_id: str) -> dict[str, Any]:
    """Read the content of an entry file by its ID.

    Args:
        entry_id (str): The ID of the entry file.

    Returns:
        dict[str, Any]: The content of the entry file as a dictionary.
    """
    entry_file = demisto.getFilePath(entry_id)

    with open(entry_file["path"], "rb") as handler:
        content = json.load(handler)

    return content


def find_rule(policy: dict, rule_name: str) -> dict[str, Any] | None:
    """Find a rule by its name in the policy."""
    return next(
        (rule for rule in policy.get("rules", []) if rule.get("rule_name") == rule_name), None
    )


def find_exception_rule(exception_rules: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    """Find a rule by its name in the policy."""
    return next((rule for rule in exception_rules if rule.get("exception_rule_name") == name), None)


def main():  # pragma: no cover
    command = demisto.command()
    params = demisto.params()
    args = demisto.args()
    demisto.debug(f"Command being called is {command}")
    base_url: str = params.get("url")
    username: str = params.get("credentials", {}).get("identifier", "")
    password: str = params.get("credentials", {}).get("password", "")
    commands: dict[str, Callable] = {
        f"{INTEGRATION_NAME}-policy-list": list_policy_command,
        f"{INTEGRATION_NAME}-policy-rule-list": list_policy_rule_command,
        f"{INTEGRATION_NAME}-rule-exception-list": list_exception_rule_command,
        f"{INTEGRATION_NAME}-rule-severity-action-get": get_rule_severity_action_command,
        f"{INTEGRATION_NAME}-rule-source-destination-get": get_rule_source_destination_command,
        f"{INTEGRATION_NAME}-rule-create": create_rule_command,
        f"{INTEGRATION_NAME}-rule-update": update_rule_command,
        f"{INTEGRATION_NAME}-rule-severity-action-update": update_rule_severity_action_command,
        f"{INTEGRATION_NAME}-rule-source-destination-update": update_rule_source_destination_command,
        f"{INTEGRATION_NAME}-rule-exception-create": create_exception_rule_command,
        f"{INTEGRATION_NAME}-rule-exception-update": update_exception_rule_command,
        f"{INTEGRATION_NAME}-incident-list": list_incidents_command,
        f"{INTEGRATION_NAME}-incident-update": update_incident_command,
        "get-modified-remote-data": get_modified_remote_data_command,
        "update-remote-system": update_remote_system,
        "get-remote-data": get_remote_data_command,
    }

    try:
        client = Client(
            base_url=base_url,
            verify=not params.get("insecure", False),
            proxy=params.get("proxy", False),
            username=username,
            password=password,
            utc_now=datetime.utcnow(),
        )
        if command == "test-module":
            return_results(test_module(client))
        elif command == "forcepoint-dlp-get-events":
            results, events = get_events_command(client, args)
            return_results(results)

            if argToBoolean(args.get("should_push_events")):
                send_events_to_xsiam(events, VENDOR, PRODUCT)  # noqa
        elif command == "fetch-events":
            max_fetch = arg_to_number(params.get("max_fetch")) or DEFAULT_MAX_FETCH
            fetch_events(client, max_fetch)
        elif command == "fetch-incidents":
            max_fetch=arg_to_number(params.get("max_fetch")) or DEFAULT_LIMIT
            first_fetch = (
                arg_to_datetime(params.get("first_fetch", "1 day"), settings=DATEPARSER_SETTINGS)
            )

            current_run, incidents = fetch_incidents(
                client=client,
                last_run=demisto.getLastRun(),
                first_fetch=first_fetch,
                max_fetch=max_fetch,
                mirror_direction=MIRROR_DIRECTION_MAPPING.get(
                    params.get("mirror_direction", "None")
                ),
            )

            demisto.debug(f"fetch: Setting last run to {current_run}.")
            demisto.debug(f"fetch: Fetched {len(incidents)} incidents.")
            demisto.setLastRun(current_run)
            demisto.incidents(incidents)
        elif command == "get-mapping-fields":
            return_results(get_mapping_fields_command())
        elif command in commands:
            return_results(commands[command](client, args))
        else:
            raise NotImplementedError(f"{command} command is not implemented.")

    # Log exceptions
    except Exception as e:
        return_error(f"Failed to execute {demisto.command()} command. Error: {str(e)}")


if __name__ in ("__main__", "__builtin__", "builtins"):  # pragma: no cover
    main()
