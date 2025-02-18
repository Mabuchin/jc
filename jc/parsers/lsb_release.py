"""jc - JSON Convert `lsb_release` command parser

This parser is an alias to the Key/Value parser (`--kv`).

Usage (cli):

    $ lsb_release -a | jc --lsb-release

or
    $ jc lsb_release -a

Usage (module):

    import jc
    result = jc.parse('lsb_release', lsb_release_command_output)

Schema:

    {
        "<key>":     string
    }

Examples:

    $ lsb_release -a | jc --lsb-release -p
    {
      "Distributor ID": "Ubuntu",
      "Description": "Ubuntu 16.04.6 LTS",
      "Release": "16.04",
      "Codename": "xenial"
    }
"""
from jc.jc_types import JSONDictType
import jc.parsers.kv
import jc.utils


class info():
    """Provides parser metadata (version, author, etc.)"""
    version = '1.0'
    description = '`lsb_release` command parser'
    author = 'Kelly Brazil'
    author_email = 'kellyjonbrazil@gmail.com'
    details = 'Using the Key/Value parser'
    compatible = ['linux', 'darwin', 'cygwin', 'win32', 'aix', 'freebsd']
    magic_commands = ['lsb_release']
    tags = ['command']


__version__ = info.version


def _process(proc_data: JSONDictType) -> JSONDictType:
    """
    Final processing to conform to the schema.

    Parameters:

        proc_data:   (Dictionary) raw structured data to process

    Returns:

        Dictionary. Structured to conform to the schema.
    """
    return jc.parsers.kv._process(proc_data)


def parse(
    data: str,
    raw: bool = False,
    quiet: bool = False
) -> JSONDictType:
    """
    Main text parsing function

    Parameters:

        data:        (string)  text data to parse
        raw:         (boolean) unprocessed output if True
        quiet:       (boolean) suppress warning messages if True

    Returns:

        Dictionary. Raw or processed structured data.
    """
    jc.utils.compatibility(__name__, info.compatible, quiet)
    raw_output = jc.parsers.kv.parse(data, raw, quiet)

    return raw_output if raw else _process(raw_output)
