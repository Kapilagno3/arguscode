import pytest
from app.parser import extract_ast_metadata


def test_extract_ast_valid_functions_and_classes():
    code = '''
import os
from typing import List, Optional

class UserManager(BaseService):
    """Manages user accounts and profile data."""
    def __init__(self, db_url: str):
        self.db_url = db_url

    def get_user(self, user_id: int) -> Optional[dict]:
        """Fetch user by id."""
        if user_id <= 0:
            return None
        return {"id": user_id, "name": "Alice"}

def calculate_total(items: List[float], tax_rate: float = 0.05) -> float:
    """Calculate total price including tax."""
    total = 0.0
    for item in items:
        if item > 0:
            total += item
    return total * (1 + tax_rate)
'''
    metadata = extract_ast_metadata(code)
    assert metadata["is_valid_syntax"] is True
    assert metadata["error"] is None

    # Check imports
    imports = metadata["imports"]
    assert any("import os" in imp or imp == "os" for imp in imports)
    assert any("typing" in imp for imp in imports)

    # Check classes
    classes = metadata["classes"]
    assert len(classes) == 1
    assert classes[0]["name"] == "UserManager"
    assert "BaseService" in classes[0]["bases"]
    assert "get_user" in classes[0]["methods"]
    assert "__init__" in classes[0]["methods"]

    # Check functions
    func_names = [f["name"] for f in metadata["functions"]]
    assert "calculate_total" in func_names
    assert "get_user" in func_names

    calc_func = next(f for f in metadata["functions"] if f["name"] == "calculate_total")
    assert "items" in calc_func["args"]
    assert "tax_rate" in calc_func["args"]
    assert calc_func["returns"] == "float"
    assert "Calculate total price" in calc_func["docstring"]

    # Complexity score should be > 1
    assert metadata["complexity_score"] > 3


def test_extract_ast_syntax_error():
    broken_code = '''
def broken_function(
    print("missing closing paren"
'''
    metadata = extract_ast_metadata(broken_code)
    assert metadata["is_valid_syntax"] is False
    assert metadata["error"] is not None
    assert metadata["error_line"] is not None
    assert metadata["functions"] == []
    assert metadata["classes"] == []


def test_extract_ast_complexity_calculation():
    complex_code = '''
def complex_algorithm(x: int, y: int) -> int:
    result = 0
    if x > 0:
        for i in range(x):
            if i % 2 == 0:
                result += i
            elif i % 3 == 0:
                result += i * 2
            else:
                result += 1
    while y > 0:
        try:
            with open("log.txt", "w") as f:
                f.write(str(y))
        except Exception:
            pass
        y -= 1
    return result
'''
    metadata = extract_ast_metadata(complex_code)
    assert metadata["is_valid_syntax"] is True
    # Base 1 + if(1) + for(1) + if(1) + elif(1) + while(1) + try/except(1) + with(1) = 8
    assert metadata["complexity_score"] >= 7


def test_extract_ast_empty_code():
    metadata = extract_ast_metadata("")
    assert metadata["is_valid_syntax"] is True
    assert metadata["lines_of_code"] == 0
    assert metadata["complexity_score"] == 1
    assert metadata["functions"] == []
