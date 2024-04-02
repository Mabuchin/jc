"""jc - JSON Convert `traceroute` command output streaming parser

> This streaming parser outputs JSON Lines (cli) or returns an Iterable of
> Dictionaries (module)

Supports `traceroute` and `traceroute6` output.

> Note: On some operating systems you will need to redirect `STDERR` to
> `STDOUT` for destination info since the header line is sent to
> `STDERR`. A warning message will be printed to `STDERR` if the
> header row is not found.
>
> e.g. `$ traceroute 8.8.8.8 2>&1 | jc --traceroute-s`

Usage (cli):

    $ traceroute 1.2.3.4 | jc --traceroute-s

Usage (module):

    import jc
    result = jc.parse('traceroute_s', traceroute_command_output.splitlines())

Schema:

    {
      "type":                       string,   # [0]
      "destination_ip":             string,
      "destination_name":           string,
      "hops": [
        {
          "hop":                integer,
          "probes": [
            {
              "annotation":     string,
              "asn":            integer,
              "ip":             string,
              "name":           string,
              "rtt":            float
            }
          ]
        }
      ],
      # below object only exists if using -qq or ignore_exceptions=True
      "_jc_meta": {
        "success":                  boolean,  # false if error parsing
        "error":                    string,   # exists if "success" is false
        "line":                     string    # exists if "success" is false
      }
    }

    [0] 'header', 'hop', 'error', etc. See `_error_type.type_map`
        for all options.

Examples:


"""
import json
import re
from decimal import Decimal
import jc.utils
from jc.streaming import (
    add_jc_meta, streaming_input_type_check, streaming_line_input_type_check, raise_or_yield
)


class info():
    """Provides parser metadata (version, author, etc.)"""
    version = '1.0'
    description = '`traceroute` and `traceroute6` command streaming parser'
    author = 'Kelly Brazil'
    author_email = 'kellyjonbrazil@gmail.com'
    details = 'Using the trparse library by Luis Benitez at https://github.com/lbenitez000/trparse'
    compatible = ['linux', 'darwin', 'freebsd']
    magic_commands = ['traceroute-s', 'traceroute6-s']
    tags = ['command']
    streaming = True


__version__ = info.version

'''
Copyright (C) 2015 Luis Benitez

Parses the output of a traceroute execution into an AST (Abstract Syntax Tree).

The MIT License (MIT)

Copyright (c) 2014 Luis Benitez

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
'''

RE_HEADER = re.compile(r'traceroute to (\S+)\s+\((\S+)\), (\d+) hops max, (\d+) byte packets')
RE_PROBE = re.compile(r'(\S+) \((\S+)\)(?: \[(AS\d+|[\*!]+)\])?\s*((?:\d+\.\d+ ms(?: \!\S+)?\s*)+)')
RE_PROBE_RTT_ANNOTATION = re.compile(r'(\d+\.\d+) ms(?: \!(\S+))?')
RE_HOP = re.compile(r'^\s*(\d+)?\s+(.+)$')

class _Hop(object):
    def __init__(self, idx):
        self.type = 'hop'
        self.idx = idx  # Hop count, starting at 1 (usually)
        self.probes = []  # Series of Probe instances

    def add_probe(self, probe):
        """Adds a Probe instance to this hop's results."""
        if self.probes:
            probe_last = self.probes[-1]
            if not probe.ip:
                probe.ip = probe_last.ip
                probe.name = probe_last.name
        self.probes.append(probe)

    def __str__(self):
        text = "{:>3d} ".format(self.idx)
        text_len = len(text)
        for n, probe in enumerate(self.probes):
            text_probe = str(probe)
            if n:
                text += (text_len * " ") + text_probe
            else:
                text += text_probe
        text += "\n"
        return text

    def __dict__(self):
        return {
            'type': self.type,
            'hop': self.idx,
            'probes': [probe.__dict__() for probe in self.probes]
        }


class _Probe(object):
    def __init__(self, name=None, ip=None, asn=None, rtt=None, annotation=None):
        self.name = name
        self.ip = ip
        self.asn = asn  # Autonomous System number
        self.rtt = rtt  # RTT in ms
        self.annotation = annotation  # Annotation, such as !H, !N, !X, etc

    def __str__(self):
        text = ""
        if self.asn is not None:
            text += "[AS{:d}] ".format(self.asn)
        if self.rtt:
            text += "{:s} ({:s}) {:1.3f} ms".format(self.name, self.ip, self.rtt)
        else:
            text = "*"
        if self.annotation:
            text += " {:s}".format(self.annotation)
        text += "\n"
        return text

    def __dict__(self):
        return {
            'annotation': self.annotation,
            'asn': self.asn,
            'ip': self.ip,
            'name': self.name,
            'rtt': str(self.rtt)
        }


def _parse_hop(line):
    # Skip empty lines
    if not line:
        return None

    hop_match = RE_HOP.match(line)
    if hop_match.group(1):
        hop_index = int(hop_match.group(1))
        hop = _Hop(hop_index)

        hop_string = hop_match.group(2)
        if not RE_PROBE.match(hop_string):
            hop.probes = [_Probe(name="*") for _ in range(3)]
            return hop

        # Find all probes for the current hop
        probes = RE_PROBE.findall(hop_string)
        probes_list = []
        # Build probes list for current hop
        for name, ip, asn, latencies_str in probes:
            matches = RE_PROBE_RTT_ANNOTATION.findall(latencies_str)
            latencies_annotations = [(float(lat), ann if ann else None) for lat, ann in matches]
            parsed_asn = asn[2:] if asn.startswith("AS") else asn
            for latency, annotation in latencies_annotations:
                _probe = _Probe(
                    name=name,
                    ip=ip,
                    asn=parsed_asn,
                    rtt=latency,
                    annotation=annotation
                )
                probes_list.append(_probe)
        hop.probes = probes_list
    return hop


class ParseError(Exception):
    pass


########################################################################################

def _process(proc_data):
    """
    Final processing to conform to the schema.

    Parameters:

        proc_data:   (Dictionary) raw structured data to process

    Returns:

        Dictionary. Structured to conform to the schema.
    """
    int_list = {'hop'}
    float_list = {'rtt'}

    for key in proc_data:
        if 'probes' in proc_data:
            for item in proc_data['probes']:
                for inner_key in item:
                    if inner_key in int_list:
                        item[inner_key] = jc.utils.convert_to_int(item[inner_key])
                    if inner_key in float_list:
                        item[inner_key] = jc.utils.convert_to_float(item[inner_key])
        if key in int_list:
            proc_data[key] = jc.utils.convert_to_int(proc_data[key])
        if key in float_list:
            proc_data[key] = jc.utils.convert_to_float(proc_data[key])

    return proc_data


@add_jc_meta
def parse(data, raw=False, quiet=False, ignore_exceptions=False):
    """
    Main text parsing function. Returns an iterable object.

    Parameters:

        data:              (iterable) line-based text data to parse
                                      (e.g. sys.stdin or str.splitlines() output)

        raw:               (boolean) unprocessed output if True
        quiet:             (boolean) suppress warning messages if True
        ignore_exceptions: (boolean) ignore exceptions if True

    Returns:

        Iterable of Dictionary objects.

    """
    jc.utils.compatibility(__name__, info.compatible, quiet)
    streaming_input_type_check(data)

    for line in data:
        try:
            output_line = {}
            streaming_line_input_type_check(line)
            # skip blank lines
            if not line.strip():
                continue

            if 'traceroute: Warning: ' in line and 'traceroute6: Warning: ' in line:
                continue

            # parse for header line
            if line.startswith('traceroute to ') or line.startswith('traceroute6 to '):
                match_dest = RE_HEADER.search(line)
                if match_dest:
                    output_line = {
                        'type': 'header',
                        'destination_ip': match_dest.group(2),
                        'destination_name': match_dest.group(1),
                        'max_hops': match_dest.group(3),
                        'send_bytes': match_dest.group(4),
                    }
            else:
                parsed_line = _parse_hop(line)
                if parsed_line:
                    output_line = parsed_line.__dict__()

            # yield the output line if it has data
            if output_line:
                yield output_line if raw else _process(output_line)
            else:
                continue
        except Exception as e:
            yield raise_or_yield(ignore_exceptions, e, line)
