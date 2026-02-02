#pragma once
#include <string_view>

// 1. Invalid JSON - missing closing brace
constexpr std::string_view INVALID_SHORT_JSON_1 = R"(
{
    "name": "test",
    "value": 42
)";

// 2. Empty JSON object
constexpr std::string_view EMPTY_JSON_2 = "";

// 3. Short valid JSON
constexpr std::string_view SHORT_VALID_JSON_3 = R"(
{
    "name": "John",
    "age": 30,
    "active": true
}
)";

// 3. Valid schema that matches SHORT_VALID_JSON
constexpr std::string_view SHORT_VALID_SCHEMA_3 = R"(
{
    "type": "object",
    "properties": {
        "name": {
            "type": "string"
        },
        "age": {
            "type": "integer",
            "minimum": 0
        },
        "active": {
            "type": "boolean"
        }
    },
    "required": ["name", "age", "active"],
    "additionalProperties": false
}
)";

// 3. Invalid schema - structurally valid JSON, but won't validate SHORT_VALID_JSON
// (expects different properties)
constexpr std::string_view SHORT_INVALID_SCHEMA_3 = R"(
{
    "type": "object",
    "properties": {
        "username": {
            "type": "string"
        },
        "count": {
            "type": "number"
        }
    },
    "required": ["username", "count"],
    "additionalProperties": false
}
)";

// 4. Config JSON - missing valid and short.
constexpr std::string_view CONFIG_JSON_ONLY_FEATURES_4 = R"(
{
    "features": {}
})";

constexpr std::string_view REAL_SCHEMA_4 = R"(
{
    "$schema": "http://json-schema.org/draft-07/schema#",
    "title": "OWLSM Configuration Schema",
    "type": "object",
    "additionalProperties": false,
    "properties": {
        "features": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "file_monitoring": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "enabled": {
                            "type": "boolean"
                        },
                        "events": {
                            "type": "object",
                            "additionalProperties": false,
                            "properties": {
                                "chmod": {
                                    "type": "boolean"
                                },
                                "chown": {
                                    "type": "boolean"
                                },
                                "file_create": {
                                    "type": "boolean"
                                },
                                "unlink": {
                                    "type": "boolean"
                                },
                                "rename": {
                                    "type": "boolean"
                                },
                                "write": {
                                    "type": "boolean"
                                },
                                "read": {
                                    "type": "boolean"
                                }
                            }
                        }
                    }
                },
                "network_monitoring": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {
                        "enabled": {
                            "type": "boolean"
                        }
                    }
                }
            }
        },
        "userspace": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "max_events_queue_size": {
                    "type": "integer",
                    "minimum": 1
                },
                "output_type": {
                    "$ref": "#/definitions/OUTPUT_TYPE"
                },
                "log_level": {
                    "$ref": "#/definitions/LOG_LEVEL"
                },
                "set_limits": {
                    "type": "boolean"
                }
            }
        },
        "kernel": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "log_level": {
                    "$ref": "#/definitions/LOG_LEVEL"
                }
            }
        },
        "rules": {
            "type": "object",
            "additionalProperties": false,
            "required": ["id_to_string", "id_to_predicate", "id_to_ip", "rules"],
            "properties": {
                "id_to_string": {
                    "type": "object",
                    "additionalProperties": {
                        "$ref": "#/definitions/rule_string_t"
                    }
                },
                "id_to_predicate": {
                    "type": "object",
                    "minProperties": 1,
                    "additionalProperties": {
                        "$ref": "#/definitions/predicate_t"
                    }
                },
                "id_to_ip": {
                    "type": "object",
                    "additionalProperties": {
                        "$ref": "#/definitions/rule_ip_t"
                    }
                },
                "rules": {
                    "type": "array",
                    "minItems": 0,
                    "items": {
                        "$ref": "#/definitions/rule_t"
                    }
                }
            }
        }
    },
    "definitions": {
        "rule_string_t": {
            "type": "object",
            "required": ["value", "is_contains"],
            "additionalProperties": false,
            "properties": {
                "value": {
                    "type": "string",
                    "maxLength": 32
                },
                "is_contains": {
                    "type": "boolean"
                }
            }
        },
        "rule_ip_t": {
            "type": "object",
            "required": ["ip", "cidr", "ip_type"],
            "additionalProperties": false,
            "properties": {
                "ip": {
                    "type": "string"
                },
                "cidr": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 128
                },
                "ip_type": {
                    "type": "integer",
                    "enum": [2, 10]
                }
            }
        },
        "predicate_t": {
            "type": "object",
            "required": ["field", "comparison_type", "string_idx", "numerical_value"],
            "additionalProperties": false,
            "properties": {
                "field": {
                    "type": "string"
                },
                "comparison_type": {
                    "type": "string",
                    "enum": [
                        "exactmatch",
                        "contains",
                        "startswith",
                        "endswith",
                        "equal",
                        "above",
                        "below",
                        "equal_above",
                        "equal_below"
                    ]
                },
                "string_idx": {
                    "type": "integer",
                    "minimum": -1
                },
                "numerical_value": {
                    "type": "integer",
                    "minimum": -1
                }
            },
            "oneOf": [
                {
                    "properties": {
                        "string_idx": {
                            "const": -1
                        },
                        "numerical_value": {
                            "type": "integer",
                            "minimum": 0
                        }
                    }
                },
                {
                    "properties": {
                        "string_idx": {
                            "type": "integer",
                            "minimum": 0
                        },
                        "numerical_value": {
                            "const": -1
                        }
                    }
                }
            ]
        },
        "token_t": {
            "type": "object",
            "required": ["operator_type"],
            "additionalProperties": false,
            "properties": {
                "operator_type": {
                    "type": "string",
                    "enum": [
                        "OPERATOR_PREDICATE",
                        "OPERATOR_AND",
                        "OPERATOR_OR",
                        "OPERATOR_NOT"
                    ]
                },
                "predicate_idx": {
                    "type": "integer",
                    "minimum": 0
                }
            },
            "if": {
                "properties": {
                    "operator_type": { "const": "OPERATOR_PREDICATE" }
                }
            },
            "then": {
                "required": ["predicate_idx"]
            }
        },
        "rule_t": {
            "type": "object",
            "required": ["id", "action", "applied_events", "tokens"],
            "additionalProperties": false,
            "properties": {
                "id": {
                    "type": "integer",
                    "minimum": 1
                },
                "description": {
                    "type": "string"
                },
                "action": {
                    "type": "string",
                    "enum": [
                        "ALLOW_EVENT",
                        "BLOCK_EVENT",
                        "BLOCK_KILL_PROCESS",
                        "BLOCK_KILL_PROCESS_KILL_PARENT",
                        "KILL_PROCESS",
                        "EXCLUDE_EVENT"
                    ]
                },
                "min_version": {
                    "type": "string",
                    "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$"
                },
                "max_version": {
                    "type": "string",
                    "pattern": "^[0-9]+\\.[0-9]+\\.[0-9]+$"
                },
                "applied_events": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "string",
                        "enum": [
                            "EXEC",
                            "FORK",
                            "EXIT",
                            "FILE_CREATE",
                            "CHOWN",
                            "CHMOD",
                            "WRITE",
                            "READ",
                            "UNLINK",
                            "RENAME",
                            "NETWORK"
                        ]
                    }
                },
                "tokens": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "$ref": "#/definitions/token_t"
                    }
                }
            }
        },
        "LOG_LEVEL": {
            "type": "string",
            "enum": [
                "LOG_LEVEL_DEBUG",
                "LOG_LEVEL_INFO",
                "LOG_LEVEL_WARNING",
                "LOG_LEVEL_ERROR"
            ]
        },
        "OUTPUT_TYPE": {
            "type": "string",
            "enum": [
                "JSON",
                "PROTOBUF"
            ]
        }
    }
}
)";

constexpr std::string_view REAL_JSON_5 = R"(
{
    "features": {
        "file_monitoring": {
            "enabled": true,
            "events": {
                "chmod": true,
                "chown": true,
                "file_create": true,
                "unlink": false,
                "rename": true,
                "write": true,
                "read": true
            }
        },
        "network_monitoring": {
            "enabled": true
        }
    },
    "userspace": {
        "max_events_queue_size": 55,
        "output_type": "JSON",
        "log_level": "LOG_LEVEL_WARNING"
    },
    "kernel": {
        "log_level": "LOG_LEVEL_DEBUG"
    },
    "rules": {
        "id_to_string": {
            "0": {
                "value": ".ssh/id_rsa",
                "is_contains": true
            },
            "1": {
                "value": "curl",
                "is_contains": false
            }
        },
        "id_to_predicate": {
            "0": {
                "field": "target.file.path",
                "comparison_type": "contains",
                "string_idx": 0,
                "numerical_value": -1
            },
            "1": {
                "field": "process.file.filename",
                "comparison_type": "endswith",
                "string_idx": 1,
                "numerical_value": -1
            },
            "2": {
                "field": "process.pid",
                "comparison_type": "equal",
                "string_idx": -1,
                "numerical_value": 1000
            }
        },
        "id_to_ip": {},
        "rules": [
            {
                "id": 100,
                "description": "Test rule",
                "action": "BLOCK_EVENT",
                "applied_events": ["READ", "WRITE"],
                "tokens": [
                    {
                        "operator_type": "OPERATOR_PREDICATE",
                        "predicate_idx": 0
                    },
                    {
                        "operator_type": "OPERATOR_PREDICATE",
                        "predicate_idx": 1
                    },
                    {
                        "operator_type": "OPERATOR_AND"
                    },
                    {
                        "operator_type": "OPERATOR_PREDICATE",
                        "predicate_idx": 2
                    },
                    {
                        "operator_type": "OPERATOR_NOT"
                    },
                    {
                        "operator_type": "OPERATOR_AND"
                    }
                ]
            }
        ]
    }
}
)";


// Test JSON: string value too long (> 32 chars)
constexpr std::string_view INVALID_STRING_TOO_LONG_JSON = R"(
{
    "rules": {
        "id_to_string": {
            "0": {
                "value": "this_string_is_way_too_long_and_exceeds_the_maximum_length_of_32_characters",
                "is_contains": true
            }
        },
        "id_to_predicate": {
            "0": {
                "field": "target.file.path",
                "comparison_type": "contains",
                "string_idx": 0,
                "numerical_value": -1
            }
        },
        "id_to_ip": {},
        "rules": []
    }
})";

// Test JSON: is_contains not boolean
constexpr std::string_view INVALID_IS_CONTAINS_NOT_BOOLEAN_JSON = R"(
{
    "rules": {
        "id_to_string": {
            "0": {
                "value": "test",
                "is_contains": "true"
            }
        },
        "id_to_predicate": {
            "0": {
                "field": "target.file.path",
                "comparison_type": "contains",
                "string_idx": 0,
                "numerical_value": -1
            }
        },
        "id_to_ip": {},
        "rules": []
    }
})";

// Test JSON: invalid field name
constexpr std::string_view INVALID_FIELD_NAME_JSON = R"(
{
    "rules": {
        "id_to_string": {
            "0": {
                "value": "test",
                "is_contains": true
            }
        },
        "id_to_predicate": {
            "0": {
                "field": "invalid.field.name",
                "comparison_type": "contains",
                "string_idx": 0,
                "numerical_value": -1
            }
        },
        "id_to_ip": {},
        "rules": []
    }
})";

// Test JSON: both string_idx and numerical_value are not -1
constexpr std::string_view INVALID_BOTH_INDICES_SET_JSON = R"(
{
    "rules": {
        "id_to_string": {
            "0": {
                "value": "test",
                "is_contains": true
            }
        },
        "id_to_predicate": {
            "0": {
                "field": "target.file.path",
                "comparison_type": "contains",
                "string_idx": 0,
                "numerical_value": 100
            }
        },
        "id_to_ip": {},
        "rules": []
    }
})";

// Test JSON: rule with 0 tokens (minItems is 0, so this should actually pass schema validation)
constexpr std::string_view RULE_WITH_ZERO_TOKENS_JSON = R"(
{
    "rules": {
        "id_to_string": {},
        "id_to_ip": {},
        "id_to_predicate": {
            "0": {
                "field": "target.file.path",
                "comparison_type": "contains",
                "string_idx": 0,
                "numerical_value": -1
            }
        },
        "rules": [
            {
                "id": 1,
                "action": "BLOCK_EVENT",
                "applied_events": ["READ"],
                "tokens": []
            }
        ]
    }
})";

// Test JSON: empty id_to_predicate (should fail - minProperties: 1)
constexpr std::string_view INVALID_EMPTY_ID_TO_PREDICATE_JSON = R"(
{
    "rules": {
        "id_to_string": {
            "0": {
                "value": "test",
                "is_contains": true
            }
        },
        "id_to_predicate": {},
        "id_to_ip": {},
        "rules": []
    }
})";

// Test JSON: empty id_to_string (should pass - no minProperties constraint)
constexpr std::string_view VALID_EMPTY_ID_TO_STRING_JSON = R"(
{
    "rules": {
        "id_to_string": {},
        "id_to_predicate": {
            "0": {
                "field": "process.pid",
                "comparison_type": "equal",
                "string_idx": -1,
                "numerical_value": 1000
            }
        },
        "id_to_ip": {},
        "rules": [
            {
                "id": 1,
                "action": "BLOCK_EVENT",
                "applied_events": ["READ"],
                "tokens": [
                    {
                        "operator_type": "OPERATOR_PREDICATE",
                        "predicate_idx": 0
                    }
                ]
            }
        ]
    }
})";