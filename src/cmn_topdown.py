#!/usr/bin/python3

"""
Top-down performance analysis methodology for CMN interconnect.
"""

from __future__ import print_function

import argparse
import atexit
import json
import os
import shlex
import subprocess
import sys

import cmn_events
import cmn_json
import cmn_perfcheck
import cmn_perfstat
import cmn_topdown_recipes
import cmnwatch
from cmn_enum import *
from memsize_str import memsize_str


TOP_CAT = "#all"
DEFAULT_RECIPE_PATHS = [os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data/recipes")]


class TopdownError(Exception):
    """Base exception for top-down planning, measurement, and formatting failures."""
    pass


class RecipeError(TopdownError):
    """Raised when a recipe is invalid or cannot be normalized into an execution plan."""
    pass


class TopdownEnvironmentError(TopdownError):
    """Raised when required PMU or perf capabilities are unavailable in the current environment."""
    pass


class MeasurementError(TopdownError):
    """Raised when a planned measurement cannot be executed or reduced into a valid result."""
    pass


class MetricPlan(object):
    """A single concrete perf event plus the category updates that should consume its rate."""
    def __init__(self, actions, event, mesh_instance=None, mesh_scoped=False, aggregate_cmn_event=False, per_node_cpu_event=False):
        self.actions = actions
        self.event = event
        self.mesh_instance = mesh_instance
        self.mesh_scoped = mesh_scoped
        self.aggregate_cmn_event = aggregate_cmn_event
        self.per_node_cpu_event = per_node_cpu_event


class TopdownPlan(object):
    """An execution-ready recipe tree containing concrete metrics and any nested subplans."""
    def __init__(self, name, desc=None, categories=None, rate_bandwidth=None, metrics=None, subplans=None, recipe=None):
        self.name = name
        self.desc = desc
        self.categories = list(categories or [])
        self.rate_bandwidth = rate_bandwidth
        self.metrics = list(metrics or [])
        self.subplans = list(subplans or [])
        self.recipe = recipe


class TopdownRunResult(object):
    """Measured output for a plan, including the local analysis and any child results."""
    def __init__(self, plan, analysis=None, mesh_analyses=None, subresults=None):
        self.plan = plan
        self.analysis = analysis
        self.mesh_analyses = list(mesh_analyses or [])
        self.subresults = list(subresults or [])


class TopdownOptions(object):
    """Runtime options shared across planning, measurement, and output formatting."""
    def __init__(self, dominance_level=0.95, adjust=True, print_percent=True, print_rate_bandwidth=False,
                 print_decimal=False, print_recipe=False, split=False, per_mesh=False, perf_bin="perf",
                 measurement_time=None, verbose=0, recipe_paths=None):
        self.dominance_level = dominance_level
        self.adjust = adjust
        self.print_percent = print_percent
        self.print_rate_bandwidth = print_rate_bandwidth
        self.print_decimal = print_decimal
        self.print_recipe = print_recipe
        self.split = split
        self.per_mesh = per_mesh
        self.perf_bin = perf_bin
        self.measurement_time = measurement_time
        self.verbose = verbose
        self.recipe_paths = list(DEFAULT_RECIPE_PATHS if recipe_paths is None else recipe_paths)


class Topdown:
    """
    Measured top-down data for a single recipe.
    """
    def __init__(self, cats, name=None, desc=None, dominance_level=0.95, verbose=0):
        self.name = name
        self.desc = desc or name
        self.categories = list(cats)
        self.dominance_level = dominance_level
        self.verbose = verbose
        self.init_measurements()

    def init_measurements(self):
        self.rate = {None: 0.0}
        for c in self.categories:
            self.rate[c] = 0.0
        self.total_rate = None
        self.is_measured = False

    def __str__(self):
        if self.verbose >= 2:
            s = "%s, name=\"%s\", dominance_level=%.2f" % (str(self.categories), self.name, self.dominance_level)
        else:
            s = "\"%s\"" % self.name
        return "Topdown(%s)" % s

    def has_baseline(self):
        return TOP_CAT in self.categories

    @staticmethod
    def is_internal_category(cat):
        return cat is not None and cat.startswith("#")

    def add_category(self, cat):
        if cat not in self.rate:
            self.categories.append(cat)
            self.rate[cat] = 0.0

    def accumulate(self, cat, rate):
        self.rate[cat] += rate

    def proportion(self, cat):
        if self.total_rate is None or self.total_rate <= 0.0:
            raise MeasurementError("top-down result has no valid total rate")
        return self.rate[cat] / self.total_rate

    def finalize(self, adjust=True):
        rates = {}
        for cat in self.categories:
            rate = self.rate[cat]
            if adjust and rate < 0.0:
                rate = 0.0
            rates[cat] = rate
        if adjust and self.rate[None] < 0.0:
            rates[None] = 0.0
        else:
            rates[None] = self.rate[None]
        self.rate.update(rates)
        if self.has_baseline():
            self.total_rate = self.rate[TOP_CAT]
        else:
            self.total_rate = 0.0
            for cat in self.categories:
                if not self.is_internal_category(cat):
                    self.total_rate += self.rate[cat]
            self.total_rate += self.rate[None]
        if self.total_rate <= 0.0:
            raise MeasurementError("unexpected zero total after adjustment")
        return self

    def dominator(self):
        if self.dominance_level <= 0.5:
            raise MeasurementError("dominance level must be greater than 0.5")
        for c in self.categories:
            if self.is_internal_category(c):
                continue
            if self.proportion(c) >= self.dominance_level:
                return c
        return None


class PerfBackend:
    """
    Thin adapter over cmn_perfstat/cmn_perfcheck so cmn_topdown has explicit dependencies.
    """
    def __init__(self, perf_module=cmn_perfstat, perfcheck_module=cmn_perfcheck, perf_bin="perf", measurement_time=None, verbose=0):
        self.perf_module = perf_module
        self.perfcheck_module = perfcheck_module
        self.perf_bin = perf_bin
        self.measurement_time = measurement_time
        self.verbose = verbose

    def configure(self):
        self.perf_module.o_verbose = max(0, self.verbose - 1)
        self.perf_module.o_time = self.measurement_time
        self.perf_module.o_perf_bin = self.perf_bin
        self.perfcheck_module.o_perf_bin = self.perf_bin

    def check_cmn_events(self, check_rsp_dat=False):
        self.configure()
        return self.perfcheck_module.check_cmn_pmu_events(check_rsp_dat=check_rsp_dat)

    def check_cpu_events(self):
        self.configure()
        return self.perfcheck_module.check_cpu_pmu_events()

    def perf_rate(self, events):
        self.configure()
        return self.perf_module.perf_rate(events, time=self.measurement_time)

    def perf_rate_per_node(self, events):
        self.configure()
        return self.perf_module.perf_rate_per_node(events, time=self.measurement_time)


class TopdownRunner:
    """Coordinates recipe normalization, event planning, environment checks, and measurement."""
    def __init__(self, system, options, backend=None):
        self.system = system
        self.options = options
        self.backend = backend if backend is not None else PerfBackend(
            perf_bin=options.perf_bin,
            measurement_time=options.measurement_time,
            verbose=options.verbose,
        )
        self.checked_cmn = False
        self.checked_cpu = False
        self._numa_node_count = None

    def ensure_cmn_available(self):
        if not self.checked_cmn:
            if not self.backend.check_cmn_events(check_rsp_dat=False):
                raise TopdownEnvironmentError("CMN perf events not available - can't do top-down analysis")
            self.checked_cmn = True
            if self.options.verbose:
                print("CMN PMU events are available", file=sys.stderr)

    def ensure_cpu_available(self):
        if not self.checked_cpu:
            if not self.backend.check_cpu_events():
                raise TopdownEnvironmentError("CPU perf events not available - can't do top-down analysis")
            self.checked_cpu = True
            if self.options.verbose:
                print("CPU PMU events are available", file=sys.stderr)

    def build_plan(self, recipe):
        plan = TopdownPlan(
            name=recipe["name"],
            desc=recipe.get("description", recipe["name"]),
            categories=list(recipe.get("categories", [])),
            rate_bandwidth=recipe.get("rate_bandwidth", None),
            recipe=recipe,
        )
        for metric in recipe.get("measure", []):
            plan.metrics.extend(self._metric_plans(metric))
        for subrecipe in recipe.get("subrecipes", []):
            plan.subplans.append(self.build_plan(subrecipe))
        return plan

    def _metric_plans(self, metric):
        if "measure" not in metric:
            raise RecipeError("measure entry is missing 'measure'")
        actions = metric["measure"]
        if "event" in metric or "ports" in metric:
            self.ensure_cmn_available()
        if "event" in metric:
            return [MetricPlan(actions=actions, event=self._cmn_event_name(metric["event"]), mesh_scoped=True, aggregate_cmn_event=True)]
        if "ports" in metric:
            return self._watchpoint_metric_plans(metric, actions)
        if "cpu-event" in metric:
            self.ensure_cpu_available()
            return [MetricPlan(actions=actions, event=metric["cpu-event"], per_node_cpu_event=True)]
        if "sys-event" in metric:
            return [MetricPlan(actions=actions, event=metric["sys-event"])]
        raise RecipeError("invalid analysis recipe metric: %s" % metric)

    def _cmn_event_name(self, event_name):
        if self.system.has_HNS():
            event_name = cmn_events.hns_events.get(event_name, event_name)
        return event_name

    def _cmn_event(self, event_name, mesh_instance=None):
        pmu_name = "arm_cmn"
        if mesh_instance is not None:
            pmu_name += "_%u" % mesh_instance
        return "%s/%s/" % (pmu_name, self._cmn_event_name(event_name))

    def _watchpoint_metric_plans(self, metric, actions):
        props = decode_properties(metric["ports"])
        plans = []
        for port in self.system.ports(properties=props):
            port_actions = actions
            if self.options.split or metric.get("split", False):
                port_actions = self._split_actions(actions, port)
            watchpoint = create_watchpoint(self.system, metric, verbose=self.options.verbose)
            if watchpoint is None:
                continue
            event = port_watchpoint_event(port, watchpoint, verbose=self.options.verbose)
            plans.append(MetricPlan(actions=port_actions, event=event, mesh_instance=port.CMN().cmn_seq, mesh_scoped=True))
        return plans

    def _split_actions(self, actions, port):
        suffix = ""
        if self.system.has_multiple_cmn():
            suffix += ":M%u" % port.CMN().cmn_seq
        suffix += ":0x%x" % port.base_id()
        split_actions = []
        for action in get_actions(actions):
            if action.startswith("*"):
                split_actions.append(action)
            elif action.startswith("-"):
                split_actions.append("-%s%s" % (action[1:], suffix))
            else:
                split_actions.append("%s%s" % (action, suffix))
        return ",".join(split_actions)

    def measure_plan(self, plan):
        result = TopdownRunResult(plan=plan)
        if self._use_per_mesh_measurement(plan):
            result.mesh_analyses = self._measure_plan_per_mesh(plan)
            result.subresults = [self.measure_plan(subplan) for subplan in plan.subplans]
            return result
        if plan.metrics:
            analysis = Topdown(
                plan.categories,
                name=plan.name,
                desc=plan.desc,
                dominance_level=self.options.dominance_level,
                verbose=self.options.verbose,
            )
            events = []
            action_sets = []
            for metric in plan.metrics:
                for action in get_action_categories(metric.actions):
                    analysis.add_category(action)
                events.append(metric.event)
                action_sets.append(metric.actions)
                if self.options.verbose:
                    print("%s: add \"%s\" = %s" % (analysis, metric.actions, metric.event))
            rates = self.backend.perf_rate(events)
            for (actions, rate) in zip(action_sets, rates):
                if self.options.verbose >= 2:
                    if rate is not None:
                        print("  %14.2f  %s" % (rate, actions))
                    else:
                        print("  <rate not available>")
                if rate is None:
                    raise MeasurementError("hardware event count not collected: try running with a longer --time")
                mult = 1.0
                for action in get_actions(actions):
                    if action.startswith("-"):
                        analysis.accumulate(action[1:], -rate * mult)
                    elif action.startswith("*"):
                        mult = float(action[1:])
                    else:
                        analysis.accumulate(action, rate * mult)
            analysis.is_measured = True
            result.analysis = analysis
        result.subresults = [self.measure_plan(subplan) for subplan in plan.subplans]
        return result

    def _use_per_mesh_measurement(self, plan):
        if not self.options.per_mesh:
            return False
        if not self.system.has_multiple_cmn():
            return False
        if not plan.metrics:
            return False
        for metric in plan.metrics:
            if metric.mesh_scoped:
                continue
            if metric.per_node_cpu_event and self.can_use_per_node_cpu_events():
                continue
            else:
                return False
        return True

    def numa_node_count(self):
        if self._numa_node_count is None:
            node_dir = "/sys/devices/system/node"
            count = 0
            if os.path.isdir(node_dir):
                for name in os.listdir(node_dir):
                    if name.startswith("node") and name[4:].isdigit():
                        count += 1
            self._numa_node_count = count
        return self._numa_node_count

    def can_use_per_node_cpu_events(self):
        if not self.system.has_multiple_cmn():
            return False
        return self.numa_node_count() == len(self.system.CMNs)

    def _measure_plan_per_mesh(self, plan):
        analyses = []
        events = []
        event_meshes = []
        action_sets = []
        cpu_events = []
        cpu_action_sets = []
        mesh_events = []
        for mesh_ix in range(0, len(self.system.CMNs)):
            analyses.append(Topdown(
                plan.categories,
                name=plan.name,
                desc=plan.desc,
                dominance_level=self.options.dominance_level,
                verbose=self.options.verbose,
            ))
            mesh_events.append(0)
        for metric in plan.metrics:
            for action in get_action_categories(metric.actions):
                for analysis in analyses:
                    analysis.add_category(action)
            if metric.aggregate_cmn_event:
                for mesh_ix in range(0, len(self.system.CMNs)):
                    events.append(self._cmn_event(metric.event, mesh_instance=mesh_ix))
                    event_meshes.append(mesh_ix)
                    action_sets.append(metric.actions)
                    mesh_events[mesh_ix] += 1
            elif metric.per_node_cpu_event:
                cpu_events.append(metric.event)
                cpu_action_sets.append(metric.actions)
                for mesh_ix in range(0, len(self.system.CMNs)):
                    mesh_events[mesh_ix] += 1
            else:
                events.append(metric.event)
                event_meshes.append(metric.mesh_instance)
                action_sets.append(metric.actions)
                mesh_events[metric.mesh_instance] += 1
            if self.options.verbose:
                if metric.aggregate_cmn_event:
                    print("%s: add \"%s\" = %s (per mesh)" % (analyses[0], metric.actions, metric.event))
                elif metric.per_node_cpu_event:
                    print("%s: add \"%s\" = %s (--per-node)" % (analyses[0], metric.actions, metric.event))
                else:
                    print("%s: add \"%s\" = %s" % (analyses[metric.mesh_instance], metric.actions, metric.event))
        if events:
            rates = self.backend.perf_rate(events)
            for (actions, rate, mesh_ix) in zip(action_sets, rates, event_meshes):
                if self.options.verbose >= 2:
                    if rate is not None:
                        print("  M%u %14.2f  %s" % (mesh_ix, rate, actions))
                    else:
                        print("  M%u <rate not available>" % mesh_ix)
                if rate is None:
                    raise MeasurementError("hardware event count not collected: try running with a longer --time")
                mult = 1.0
                for action in get_actions(actions):
                    if action.startswith("-"):
                        analyses[mesh_ix].accumulate(action[1:], -rate * mult)
                    elif action.startswith("*"):
                        mult = float(action[1:])
                    else:
                        analyses[mesh_ix].accumulate(action, rate * mult)
        if cpu_events:
            node_rates = self.backend.perf_rate_per_node(cpu_events)
            assert len(node_rates) == len(self.system.CMNs), "unexpected: %u NUMA nodes but %u meshes" % (len(node_rates), len(self.system.CMNs))
            for (mesh_ix, rates) in enumerate(node_rates):
                assert len(rates) == len(cpu_action_sets), "unexpected: %u node rates but %u CPU events" % (len(rates), len(cpu_action_sets))
                for (actions, rate) in zip(cpu_action_sets, rates):
                    if self.options.verbose >= 2:
                        if rate is not None:
                            print("  M%u %14.2f  %s" % (mesh_ix, rate, actions))
                        else:
                            print("  M%u <rate not available>" % mesh_ix)
                    if rate is None:
                        raise MeasurementError("hardware event count not collected: try running with a longer --time")
                    mult = 1.0
                    for action in get_actions(actions):
                        if action.startswith("-"):
                            analyses[mesh_ix].accumulate(action[1:], -rate * mult)
                        elif action.startswith("*"):
                            mult = float(action[1:])
                        else:
                            analyses[mesh_ix].accumulate(action, rate * mult)
        for (mesh_ix, analysis) in enumerate(analyses):
            analysis.is_measured = (mesh_events[mesh_ix] != 0)
        return analyses


def get_actions(actions):
    """
    Split a measure string into individual actions.
    Actions can be:
      <category>      - add measured value to category
      -<category>     - subtract measured value from category
      *<multiplier>   - multiply subsequent values
    """
    if not isinstance(actions, str):
        raise RecipeError("measure specifier must be a string")
    action_list = [action.strip() for action in actions.split(',')]
    for action in action_list:
        if not action:
            raise RecipeError("empty action in measure specifier '%s'" % actions)
        if action.startswith("*"):
            try:
                float(action[1:])
            except ValueError:
                raise RecipeError("invalid multiplier in measure specifier '%s'" % actions)
        elif action == "-":
            raise RecipeError("invalid action in measure specifier '%s'" % actions)
    return action_list


def get_action_categories(actions):
    for action in get_actions(actions):
        if action.startswith("*"):
            continue
        if action.startswith("-"):
            yield action[1:]
        else:
            yield action


def create_watchpoint(system, metric, verbose=0):
    try:
        kwargs = {}
        if "watchpoint_up" in metric:
            kwargs.update(metric["watchpoint_up"])
            kwargs["up"] = True
        elif "watchpoint_down" in metric:
            kwargs.update(metric["watchpoint_down"])
            kwargs["up"] = False
        else:
            kwargs.update(metric["watchpoint"])
        return cmnwatch.Watchpoint(cmn_version=system.cmn_version(), **kwargs)
    except cmnwatch.WatchpointValueOutOfRange as e:
        if verbose >= 2:
            print("ignoring unavailable watchpoint: %s" % e, file=sys.stderr)
        return None
    except cmnwatch.WatchpointError as e:
        raise RecipeError("unexpected bad watchpoint: %s" % e)


def decode_properties(prop_spec):
    if isinstance(prop_spec, int):
        return prop_spec
    if not isinstance(prop_spec, str):
        raise RecipeError("invalid port specifier %r, expect e.g. 'RN-F'" % (prop_spec,))
    props = cmn_properties(prop_spec, check=False)
    if props is None:
        raise RecipeError("invalid port specifier \"%s\", expect e.g. \"RN-F\"" % prop_spec)
    return props


def port_watchpoint_events(port, watchpoint):
    return watchpoint.perf_events(cmn_instance=port.CMN().cmn_seq, nodeid=port.XP().node_id(), dev=port.port_number)


def port_watchpoint_event(port, watchpoint, verbose=0):
    watchpoint_events = port_watchpoint_events(port, watchpoint)
    if len(watchpoint_events) != 1:
        raise MeasurementError("watchpoint requires multiple groups and is not supported here: %s" % watchpoint_events)
    event = watchpoint_events[0]
    if verbose >= 2:
        print("  event: %s" % event)
    return event


def recipe_load(name, recipe_paths=None):
    recipe_paths = DEFAULT_RECIPE_PATHS if recipe_paths is None else recipe_paths
    if not name.endswith(".json"):
        name += ".json"
    if os.path.isfile(name):
        with open(name) as f:
            return json.load(f)
    for path in recipe_paths:
        filename = os.path.join(path, name)
        if os.path.isfile(filename):
            return recipe_load(filename, recipe_paths=recipe_paths)
    raise IOError(name)


def default_measurement_time(system, verbose=0):
    if not getattr(system, "CMNs", None):
        return None
    if not system.CMNs:
        return None
    cmn0 = system.CMNs[0]
    mesh_size = cmn0.dimX * cmn0.dimY
    measurement_time = 0.01 * mesh_size
    if verbose:
        print("Mesh size %ux%u: measurement time set to %.2fs" % (cmn0.dimX, cmn0.dimY, measurement_time))
    return measurement_time


def format_analysis(analysis, rate_bandwidth, options):
    analysis.finalize(adjust=options.adjust)
    lines = []
    if analysis.desc is not None:
        lines.append("%s:" % analysis.desc)
    dom = analysis.dominator()
    catlist = list(analysis.categories) + [None]
    if TOP_CAT in catlist:
        catlist.remove(TOP_CAT)
        catlist.append(TOP_CAT)
    print_rate_bandwidth = (rate_bandwidth is not None) or options.print_rate_bandwidth
    for category in catlist:
        if category is None and not analysis.rate[category]:
            continue
        if category not in (None, TOP_CAT) and analysis.is_internal_category(category):
            continue
        category_name = "(total)" if category == TOP_CAT else category if category is not None else "uncategorized"
        if print_rate_bandwidth:
            rb = rate_bandwidth or 64
            value = " %12s/s" % memsize_str(rb * analysis.rate[category], decimal=options.print_decimal)
        else:
            value = " %14.2f" % analysis.rate[category]
        if options.print_percent:
            value += " %6.1f%%" % (analysis.proportion(category) * 100.0)
        else:
            value += " %6.3f" % analysis.proportion(category)
        value += dominance_marker(category == dom)
        lines.append("  %-15s%s" % (category_name, value))
    if dom is not None:
        lines.append("Dominant category: %s" % dom)
    elif options.verbose:
        lines.append("No dominant category at %.0f%% level" % (analysis.dominance_level * 100.0))
    if options.verbose:
        lines.append("")
    return "\n".join(lines)


def format_analysis_value(analysis, category, rate_bandwidth, options):
    (value, marker) = format_analysis_value_parts(analysis, category, rate_bandwidth, options)
    return value + marker


def format_analysis_value_parts(analysis, category, rate_bandwidth, options):
    if not analysis.is_measured:
        return ("n/a", dominance_marker(False))
    print_rate_bandwidth = (rate_bandwidth is not None) or options.print_rate_bandwidth
    if print_rate_bandwidth:
        rb = rate_bandwidth or 64
        value = "%12s/s" % memsize_str(rb * analysis.rate[category], decimal=options.print_decimal)
    else:
        value = "%14.2f" % analysis.rate[category]
    if options.print_percent:
        value += " %6.1f%%" % (analysis.proportion(category) * 100.0)
    else:
        value += " %6.3f" % analysis.proportion(category)
    return (value, dominance_marker(category == analysis.dominator()))


def dominance_marker(is_dominant):
    if is_dominant:
        return " **"
    return "   "


def format_mesh_analyses(analyses, rate_bandwidth, options):
    for analysis in analyses:
        if analysis.is_measured:
            analysis.finalize(adjust=options.adjust)
    if not analyses:
        return ""
    lines = []
    desc = analyses[0].desc
    if desc is not None:
        lines.append("%s:" % desc)
    catlist = list(analyses[0].categories) + [None]
    if TOP_CAT in catlist:
        catlist.remove(TOP_CAT)
        catlist.append(TOP_CAT)
    value_width = 0
    marker_width = len(dominance_marker(False))
    headers = []
    for (mesh_ix, analysis) in enumerate(analyses):
        header = "M%u" % mesh_ix
        headers.append(header)
        value_width = max(value_width, len(header))
    row_values = {}
    for category in catlist:
        if category is None:
            if not [analysis for analysis in analyses if analysis.is_measured and analysis.rate[category]]:
                continue
        elif category != TOP_CAT and analyses[0].is_internal_category(category):
            continue
        vals = [format_analysis_value_parts(analysis, category, rate_bandwidth, options) for analysis in analyses]
        row_values[category] = vals
        for (value, marker) in vals:
            value_width = max(value_width, len(value))
    label_width = 15
    lines.append("  %-*s %s" % (label_width, "", " ".join([(header.rjust(value_width) + (" " * marker_width)) for header in headers])))
    for category in catlist:
        if category not in row_values:
            continue
        category_name = "(total)" if category == TOP_CAT else category if category is not None else "uncategorized"
        lines.append("  %-*s %s" % (label_width, category_name, " ".join([(value.rjust(value_width) + marker) for (value, marker) in row_values[category]])))
    dominators = []
    any_dom = False
    for analysis in analyses:
        dom = analysis.dominator() if analysis.is_measured else None
        if dom is None:
            dominators.append("-")
        else:
            dominators.append(dom)
            any_dom = True
    if any_dom:
        lines.append("  %-*s %s" % (label_width, "dominant", " ".join([(dom.rjust(value_width) + (" " * marker_width)) for dom in dominators])))
    elif options.verbose:
        lines.append("No dominant category at %.0f%% level" % (analyses[0].dominance_level * 100.0))
    if options.verbose:
        lines.append("")
    return "\n".join(lines)


def format_result(result, options):
    chunks = []
    if result.mesh_analyses:
        chunks.append(format_mesh_analyses(result.mesh_analyses, result.plan.rate_bandwidth, options))
    elif result.analysis is not None:
        if options.verbose:
            print("%s: completing top-down analysis" % result.analysis)
        chunks.append(format_analysis(result.analysis, result.plan.rate_bandwidth, options))
    for subresult in result.subresults:
        formatted = format_result(subresult, options)
        if formatted:
            chunks.append(formatted)
    return "\n\n".join([chunk for chunk in chunks if chunk])


def print_recipe(recipe):
    print(json.dumps(recipe, indent=4))


def select_builtin_recipes(levels):
    recipes = []
    for level in levels:
        try:
            recipes.append(cmn_topdown_recipes.BUILTIN_LEVELS[level])
        except KeyError:
            raise RecipeError("bad topdown level %s" % level)
    return recipes


def parse_args(argv):
    parser = argparse.ArgumentParser(description="Top-down performance analysis for CMN interconnect",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("--level", type=str, action="append", default=[], help="run specified top-down level")
    parser.add_argument("--all", action="store_true", help="run all top-down levels")
    parser.add_argument("--time", type=float, default=None, help="measurement time for top-down")
    parser.add_argument("--dominance-level", type=float, default=0.95, help="threshold for traffic to be considered dominant")
    parser.add_argument("--percentage", action="store_true", help="print as percentages")
    parser.add_argument("--bandwidth", action="store_true", help="print request counts as bandwidth")
    parser.add_argument("--decimal", action="store_true", help="print bandwidth as decimal (MB not MiB)")
    parser.add_argument("--recipe", type=str, action="append", help="use JSON top-down recipe")
    parser.add_argument("--recipe-path", type=str, action="append", help="additional recipe paths")
    parser.add_argument("--print-recipe", action="store_true", help="print recipe as JSON")
    parser.add_argument("--no-adjust", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--split", action="store_true", help="split measurements by port")
    parser.add_argument("--per-mesh", action="store_true", help="calculate mesh-scoped metrics per mesh")
    parser.add_argument("--perf-bin", type=str, default="perf", help="perf command")
    parser.add_argument("--cmd", type=str, help="microbenchmark to run (will be killed on exit)")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="increase verbosity")
    return parser.parse_args(argv)


def options_from_args(opts):
    recipe_paths = list(DEFAULT_RECIPE_PATHS)
    if opts.recipe_path:
        recipe_paths = opts.recipe_path + recipe_paths
    return TopdownOptions(
        dominance_level=opts.dominance_level,
        adjust=(not opts.no_adjust),
        print_percent=True if opts.percentage else True,
        print_rate_bandwidth=opts.bandwidth,
        print_decimal=opts.decimal,
        print_recipe=opts.print_recipe,
        split=opts.split,
        per_mesh=opts.per_mesh,
        perf_bin=opts.perf_bin,
        measurement_time=opts.time,
        verbose=opts.verbose,
        recipe_paths=recipe_paths,
    )


def resolved_levels(opts):
    levels = list(opts.level)
    if not levels:
        levels = ["1"] if (not opts.recipe) else []
    if opts.all or levels == ["all"]:
        levels = list(cmn_topdown_recipes.DEFAULT_LEVELS_ALL)
    return levels


def load_selected_recipes(opts, options):
    recipes = []
    recipes.extend(select_builtin_recipes(resolved_levels(opts)))
    if opts.recipe:
        for recipe_name in opts.recipe:
            recipes.append(recipe_load(recipe_name, recipe_paths=options.recipe_paths))
    return recipes


def start_workload(command):
    process = subprocess.Popen(shlex.split(command))
    atexit.register(lambda proc: proc.kill(), process)
    return process


def main(argv):
    opts = parse_args(argv)
    options = options_from_args(opts)
    recipes = load_selected_recipes(opts, options)
    if options.print_recipe:
        for recipe in recipes:
            print_recipe(recipe)
        return 0
    system = cmn_json.system_from_json_file()
    if options.measurement_time is None:
        options.measurement_time = default_measurement_time(system, verbose=options.verbose)
    if opts.cmd:
        start_workload(opts.cmd)
    print("CMN Top-down performance analysis")
    print("=================================")
    runner = TopdownRunner(system, options)
    for recipe in recipes:
        result = runner.measure_plan(runner.build_plan(recipe))
        formatted = format_result(result, options)
        if formatted:
            print("")
            print(formatted)
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except TopdownError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
