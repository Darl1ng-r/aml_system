import sys
import types
import pytest
from unittest.mock import patch, MagicMock

# Setup mock alembic and sqlalchemy modules if not installed in environment
if "alembic" not in sys.modules:
    alembic_mod = types.ModuleType("alembic")
    op_mod = MagicMock()
    alembic_mod.op = op_mod
    sys.modules["alembic"] = alembic_mod
    sys.modules["alembic.op"] = op_mod

if "sqlalchemy" not in sys.modules:
    sa_mod = types.ModuleType("sqlalchemy")
    sa_mod.inspect = MagicMock()
    sa_mod.Column = MagicMock()
    sa_mod.String = MagicMock()
    sa_mod.Boolean = MagicMock()
    sa_mod.DateTime = MagicMock()
    sa_mod.ForeignKey = MagicMock()
    sa_mod.text = MagicMock()

    pg_mod = types.ModuleType("sqlalchemy.dialects.postgresql")
    pg_mod.UUID = MagicMock()

    dialects_mod = types.ModuleType("sqlalchemy.dialects")
    dialects_mod.postgresql = pg_mod

    sa_mod.dialects = dialects_mod
    sys.modules["sqlalchemy"] = sa_mod
    sys.modules["sqlalchemy.dialects"] = dialects_mod
    sys.modules["sqlalchemy.dialects.postgresql"] = pg_mod

import importlib


def test_migration_005_and_007_modules_importable():
    """Verify Alembic migration revision modules 005 and 007 import without syntax or logic errors."""
    mod_005 = importlib.import_module("migrations.versions.005_create_pep_entities_table")
    mod_007 = importlib.import_module("migrations.versions.007_add_tenant_id_to_pep_entities")

    assert mod_005.revision == "005"
    assert mod_007.revision == "007"
    assert mod_007.down_revision == "006"


def test_migration_005_upgrade_creates_base_table_without_tenant_id():
    """Verify revision 005 creates pep_entities base table using sa.inspect guard."""
    mod_005 = importlib.import_module("migrations.versions.005_create_pep_entities_table")

    mock_bind = MagicMock()
    mock_inspector = MagicMock()
    mock_inspector.has_table.return_value = False

    with patch.object(mod_005.op, "get_bind", return_value=mock_bind), \
         patch.object(mod_005.sa, "inspect", return_value=mock_inspector), \
         patch.object(mod_005.op, "create_table") as mock_create_table:

        mod_005.upgrade()

        mock_create_table.assert_called_once()
        args, kwargs = mock_create_table.call_args
        table_name = args[0]

        assert table_name == "pep_entities"


def test_migration_007_upgrade_adds_tenant_id_when_missing():
    """Verify revision 007 adds tenant_id column and index when pep_entities exists without tenant_id."""
    mod_007 = importlib.import_module("migrations.versions.007_add_tenant_id_to_pep_entities")

    mock_bind = MagicMock()
    mock_inspector = MagicMock()
    mock_inspector.has_table.return_value = True
    mock_inspector.get_columns.return_value = [
        {"name": "id"}, {"name": "name"}, {"name": "pep_tier"}, {"name": "country"}
    ]

    with patch.object(mod_007.op, "get_bind", return_value=mock_bind), \
         patch.object(mod_007.sa, "inspect", return_value=mock_inspector), \
         patch.object(mod_007.op, "add_column") as mock_add_column, \
         patch.object(mod_007.op, "create_index") as mock_create_index, \
         patch.object(mod_007.op, "execute") as mock_execute:

        mod_007.upgrade()

        mock_add_column.assert_called_once()
        mock_create_index.assert_called_once()
        mock_execute.assert_called_once()


def test_migration_007_upgrade_skips_adding_tenant_id_when_already_present():
    """Verify revision 007 skips adding tenant_id column if it is already present in pep_entities."""
    mod_007 = importlib.import_module("migrations.versions.007_add_tenant_id_to_pep_entities")

    mock_bind = MagicMock()
    mock_inspector = MagicMock()
    mock_inspector.has_table.return_value = True
    mock_inspector.get_columns.return_value = [
        {"name": "id"}, {"name": "name"}, {"name": "pep_tier"}, {"name": "tenant_id"}
    ]

    with patch.object(mod_007.op, "get_bind", return_value=mock_bind), \
         patch.object(mod_007.sa, "inspect", return_value=mock_inspector), \
         patch.object(mod_007.op, "add_column") as mock_add_column, \
         patch.object(mod_007.op, "create_index") as mock_create_index, \
         patch.object(mod_007.op, "execute") as mock_execute:

        mod_007.upgrade()

        mock_add_column.assert_not_called()
        mock_create_index.assert_not_called()
        # RLS policies are still enforced
        mock_execute.assert_called_once()
