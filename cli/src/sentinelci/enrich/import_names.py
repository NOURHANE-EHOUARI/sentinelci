"""Reviewed import names of PyPI distributions, and packages used without an import (enrich/reachability.py).

A distribution name says little about what code imports: PyYAML is `yaml`, Pillow is `PIL`, protobuf is
`google.protobuf`. Reachability may claim `not_imported` for a PyPI package only when it is listed in
IMPORT_NAMES, so a wrong guess can never lower a score. Add an entry only after checking the wheel's
top-level modules (`top_level.txt`, or the module directories in RECORD), and keep the list sorted.

USED_WITHOUT_IMPORT lists packages that run without first-party code importing them: servers and workers
started from a command line, database drivers that frameworks load from a URL or an engine name, and
optional accelerators that libraries use when they are installed. They are never `not_imported`;
NPM_USED_WITHOUT_IMPORT is the same for npm.

Keys are PEP 503 normalized names.
"""

from __future__ import annotations

IMPORT_NAMES: dict[str, tuple[str, ...]] = {
    "aiohttp": ("aiohttp",),
    "attrs": ("attr", "attrs"),
    "babel": ("babel",),
    "bcrypt": ("bcrypt",),
    "beautifulsoup4": ("bs4",),
    "boto3": ("boto3",),
    "botocore": ("botocore",),
    "celery": ("celery",),
    "certifi": ("certifi",),
    "charset-normalizer": ("charset_normalizer",),
    "click": ("click",),
    "cryptography": ("cryptography",),
    "defusedxml": ("defusedxml",),
    "django": ("django",),
    "djangorestframework": ("rest_framework",),
    "ecdsa": ("ecdsa",),
    "fastapi": ("fastapi",),
    "flask": ("flask",),
    "grpcio": ("grpc",),
    "httpx": ("httpx",),
    "idna": ("idna",),
    "itsdangerous": ("itsdangerous",),
    "jinja2": ("jinja2",),
    "jsonschema": ("jsonschema",),
    "lxml": ("lxml",),
    "mako": ("mako",),
    "markdown": ("markdown",),
    "markupsafe": ("markupsafe",),
    "matplotlib": ("matplotlib", "mpl_toolkits", "pylab"),
    "msgpack": ("msgpack",),
    "numpy": ("numpy",),
    "opencv-python": ("cv2",),
    "pandas": ("pandas",),
    "paramiko": ("paramiko",),
    "passlib": ("passlib",),
    "pillow": ("PIL",),
    "protobuf": ("google.protobuf",),
    "psutil": ("psutil",),
    "pyasn1": ("pyasn1",),
    "pycryptodome": ("Crypto",),
    "pydantic": ("pydantic",),
    "pygments": ("pygments",),
    "pyjwt": ("jwt",),
    "pymongo": ("pymongo", "bson", "gridfs"),
    "pyopenssl": ("OpenSSL",),
    "python-dateutil": ("dateutil",),
    "python-jose": ("jose",),
    "pytz": ("pytz",),
    "pyyaml": ("yaml", "_yaml"),
    "redis": ("redis",),
    "requests": ("requests",),
    "rsa": ("rsa",),
    "scikit-learn": ("sklearn",),
    "scipy": ("scipy",),
    "six": ("six",),
    "sqlalchemy": ("sqlalchemy",),
    "starlette": ("starlette",),
    "tornado": ("tornado",),
    "tqdm": ("tqdm",),
    "urllib3": ("urllib3",),
    "websockets": ("websockets",),
    "werkzeug": ("werkzeug",),
    "xmltodict": ("xmltodict",),
}

USED_WITHOUT_IMPORT: frozenset[str] = frozenset(
    {
        # servers and workers started from a command line or a config file
        "daphne", "gunicorn", "hypercorn", "supervisor", "uvicorn", "uwsgi", "waitress",
        "eventlet", "gevent",
        # database drivers loaded from a URL or an engine name (SQLAlchemy, Django)
        "aiomysql", "aiosqlite", "asyncpg", "cx-oracle", "mysql-connector-python", "mysqlclient",
        "oracledb", "pg8000", "psycopg", "psycopg-binary", "psycopg-c", "psycopg2", "psycopg2-binary",
        "pymssql", "pymysql", "pyodbc",
        # optional accelerators and helpers that libraries use when installed
        "brotli", "brotlicffi", "email-validator", "httptools", "orjson", "python-dotenv",
        "python-multipart", "simplejson", "ujson", "uvloop", "watchfiles", "zstandard",
        # used by the standard library or by the packaging tools themselves
        "pip", "setuptools", "tzdata", "wheel",
    }
)  # fmt: skip

NPM_USED_WITHOUT_IMPORT: frozenset[str] = frozenset(
    {
        # database drivers that ORMs (Sequelize, Knex, TypeORM) load from a dialect name
        "better-sqlite3", "mariadb", "mysql", "mysql2", "oracledb", "pg", "pg-hstore", "pg-native",
        "sqlite3", "tedious",
    }
)  # fmt: skip
