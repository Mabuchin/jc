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

RE_HEADER = re.compile(r'(\S+)\s+\((\d+\.\d+\.\d+\.\d+|[0-9a-fA-F:]+)\)')
RE_PROBE_NAME_IP = re.compile(r'(\S+)\s+\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|[0-9a-fA-F:]+)\)+')
RE_PROBE_IP_ONLY = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([^\(])')
RE_PROBE_IPV6_ONLY = re.compile(r'(([a-f0-9:]+:+)+[a-f0-9]+)')
RE_PROBE_BSD_IPV6 = re.compile(r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b')
RE_HOP = re.compile(r'^\s*(\d+)?\s+(.+)$')
RE_PROBE_ASN = re.compile(r'\[AS(\d+)\]')
RE_PROBE_RTT_ANNOTATION = re.compile(r'(?:(\d+(?:\.?\d+)?)\s+ms|(\s+\*\s+))\s*(!\S*)?')

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
        probe_asn_match = RE_PROBE_ASN.search(hop_string)
        if probe_asn_match:
            probe_asn = int(probe_asn_match.group(1))
        else:
            probe_asn = None

        probe_ip_only_match = RE_PROBE_IP_ONLY.search(hop_string)
        probe_name_ip_match = RE_PROBE_NAME_IP.search(hop_string)
        probe_bsd_ipv6_match = RE_PROBE_BSD_IPV6.search(hop_string)
        probe_ipv6_only_match = RE_PROBE_IPV6_ONLY.search(hop_string)
        if probe_ip_only_match:
            probe_name = None
            probe_ip = probe_ip_only_match.group(1)
        elif probe_name_ip_match:
            probe_name = probe_name_ip_match.group(1)
            probe_ip = probe_name_ip_match.group(2)
        elif probe_bsd_ipv6_match:
            probe_name = None
            probe_ip = probe_bsd_ipv6_match.group(0)
        elif probe_ipv6_only_match:
            probe_name = None
            probe_ip = probe_ipv6_only_match.group(1)
        else:
            probe_name = None
            probe_ip = None

        probe_rtt_annotations = RE_PROBE_RTT_ANNOTATION.findall(hop_string)
        for probe_rtt_annotation in probe_rtt_annotations:
            if probe_rtt_annotation[0]:
                probe_rtt = Decimal(probe_rtt_annotation[0])
            elif probe_rtt_annotation[1]:
                probe_rtt = None
            else:
                message = f"Expected probe RTT or *. Got: '{probe_rtt_annotation[0]}'"
                raise ParseError(message)

            probe_annotation = probe_rtt_annotation[2] or None

            probe = _Probe(
                name=probe_name,
                ip=probe_ip,
                asn=probe_asn,
                rtt=probe_rtt,
                annotation=probe_annotation
            )

            # only add probe if there is data
            if any([probe_name, probe_ip, probe_asn, probe_rtt, probe_annotation]):
                hop.add_probe(probe)
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
    int_list = {'hop', 'asn'}
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
                        'destination_name': match_dest.group(1)
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
