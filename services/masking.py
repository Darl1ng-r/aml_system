"""
PII Masking Service for Auditor Persona (GAP-23)
================================================
Masks Personally Identifiable Information (PII) for AUDITOR role users
who do not have explicit elevated unmask privileges.
"""

from typing import Any, Dict, List, Union


def mask_string(val: str, mask_char: str = "*", show_start: int = 1, show_end: int = 1) -> str:
    if not val:
        return val
    s = str(val).strip()
    if len(s) <= (show_start + show_end):
        return mask_char * len(s)
    return s[:show_start] + (mask_char * (len(s) - show_start - show_end)) + s[-show_end:]


def mask_name(name: str) -> str:
    if not name:
        return name
    words = str(name).strip().split()
    masked_words = []
    for w in words:
        if len(w) <= 2:
            masked_words.append(w[0] + "*")
        else:
            masked_words.append(w[0] + ("*" * (len(w) - 2)) + w[-1])
    return " ".join(masked_words)


def mask_account_number(acc: str) -> str:
    if not acc:
        return acc
    s = str(acc).strip()
    if len(s) <= 4:
        return "****"
    return ("*" * (len(s) - 4)) + s[-4:]


def mask_pii_data(data: Union[Dict[str, Any], List[Any], Any], role: str = "AUDITOR") -> Any:
    """
    Recursively scans and masks PII fields if user role is AUDITOR or GLOBAL_AUDITOR.
    """
    if role not in ["AUDITOR", "GLOBAL_AUDITOR"]:
        return data

    if isinstance(data, list):
        return [mask_pii_data(item, role=role) for item in data]

    if isinstance(data, dict):
        masked_dict = {}
        for k, v in data.items():
            key_lower = k.lower()
            if isinstance(v, (dict, list)):
                masked_dict[k] = mask_pii_data(v, role=role)
            elif isinstance(v, str):
                if any(x in key_lower for x in ["name", "owner"]):
                    masked_dict[k] = mask_name(v)
                elif any(x in key_lower for x in ["account", "acc_num"]):
                    masked_dict[k] = mask_account_number(v)
                elif any(x in key_lower for x in ["tax_id", "ssn", "registration"]):
                    masked_dict[k] = mask_string(v, show_start=2, show_end=2)
                elif "bic" in key_lower:
                    masked_dict[k] = mask_string(v, show_start=4, show_end=0)
                else:
                    masked_dict[k] = v
            else:
                masked_dict[k] = v
        return masked_dict

    return data
