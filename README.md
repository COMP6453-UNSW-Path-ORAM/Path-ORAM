# Path-ORAM

An implemementation of the Path-ORAM protocol.
This repo contains a server and client library for Path ORAM, as well as sample server and client implementations for testing.

## Installation

In root directory, run:

```python
pip install .
# for developers 
pip install -e .[dev]
```

Running in a virtual environment (e.g., using venv) recommended for isolation from preinstalled system-level python packages.

- Now to run demo:

```python
python demo_recursive.py
```

- To run tests:

```python
pytest tests/pathoram/server
pytest tests/pathoram/client
```
