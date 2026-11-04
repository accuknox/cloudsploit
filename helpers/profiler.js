// Scan profiler, switched on with --profile.
//
// Records wall time, CPU time and memory for each stage of a scan, for every
// collector call (Service:call across all of its regions), for every plugin
// and - through a global aws-sdk listener - for every AWS request made by
// anything in the process. Stages, collectors and plugins are logged live as
// they finish, a heartbeat reports progress and memory while a long stage is
// running, and report() prints a summary at the end and can write the full
// profile as JSON.
//
// Until enable() is called every hook returns a no-op, so the engine and the
// collectors call into this unconditionally.

var fs = require('fs');
var stringify = require('fast-safe-stringify');
var { performance } = require('perf_hooks');

var SAMPLE_INTERVAL_MS = 500;
var HEARTBEAT_INTERVAL_MS = 15000;
var TOP_N = 25;
var STATUS_WORDS = ['OK', 'WARN', 'FAIL', 'UNKNOWN'];

// Taken when this module is first required. engine.js requires it ahead of
// exports.js, so the 'startup' stage covers loading every plugin.
var BOOT = {at: performance.now(), mem: process.memoryUsage(), cpu: process.cpuUsage()};

var enabled = false;
var options = {};
var timers = [];
var awsInstrumented = false;

var stages = [];
var openStages = [];
var collectorRuns = [];
var pluginRuns = [];
var awsOperations = {};
var memoryTimeline = [];
var peak = {rss: 0, heapUsed: 0};
var running = {collectors: 0, plugins: {}, awsRequests: 0};
var awsRequestsDone = 0;

var noopStage = {end: function() {}};
var noopCollector = {timeRegion: function(iterator) { return iterator; }, end: function() {}};
var noopPlugin = {end: function() {}};

var now = function() { return performance.now(); };
var sinceBoot = function(at) { return round((at === undefined ? now() : at) - BOOT.at); };
var round = function(ms) { return Math.round(ms * 10) / 10; };

var mb = function(bytes) { return (bytes / 1048576).toFixed(1) + 'MB'; };
var signedMb = function(bytes) { return (bytes >= 0 ? '+' : '') + mb(bytes); };
var formatMs = function(ms) { return ms >= 1000 ? (ms / 1000).toFixed(2) + 's' : ms.toFixed(1) + 'ms'; };
var memSummary = function(mem) { return 'rss=' + mb(mem.rss) + ' heap=' + mb(mem.heapUsed); };

var log = function(kind, message) {
    console.log('[PROFILE +' + (sinceBoot() / 1000).toFixed(1) + 's][' + kind + '] ' + message);
};

var updatePeak = function(target, mem) {
    if (mem.rss > target.rss) target.rss = mem.rss;
    if (mem.heapUsed > target.heapUsed) target.heapUsed = mem.heapUsed;
};

// Reads current memory and folds it into the overall peak and the peak of
// every stage still open.
var observe = function() {
    var mem = process.memoryUsage();
    updatePeak(peak, mem);
    openStages.forEach(function(stage) { updatePeak(stage.peak, mem); });
    return mem;
};

var errorCode = function(err) {
    if (err && typeof err === 'object') return String(err.code || err.name || 'Error');
    return String(err).slice(0, 60);
};

var countErrorCode = function(codes, err) {
    var code = errorCode(err);
    codes[code] = (codes[code] || 0) + 1;
};

var formatErrorCodes = function(codes) {
    return Object.keys(codes)
        .sort(function(a, b) { return codes[b] - codes[a]; })
        .map(function(code) { return code + 'x' + codes[code]; })
        .join(',');
};

// Counts what a collector left in the collection: the regions it reached, the
// items it returned (list entries for a regional call, resources queried for a
// postcall that runs once per dependency) and its errors by code.
var summarizeResult = function(entry) {
    var summary = {regionsCalled: 0, items: 0, errors: 0, errorCodes: {}};

    Object.keys(entry || {}).forEach(function(region) {
        var regionResult = entry[region];
        if (!regionResult || typeof regionResult !== 'object') return;

        if ('data' in regionResult || 'err' in regionResult) {
            summary.regionsCalled++;
            if (regionResult.err) {
                summary.errors++;
                countErrorCode(summary.errorCodes, regionResult.err);
            }
            if (Array.isArray(regionResult.data)) summary.items += regionResult.data.length;
            else if (regionResult.data) summary.items++;
            return;
        }

        var deps = Object.keys(regionResult);
        if (!deps.length) return;
        summary.regionsCalled++;
        deps.forEach(function(dep) {
            summary.items++;
            if (regionResult[dep] && regionResult[dep].err) {
                summary.errors++;
                countErrorCode(summary.errorCodes, regionResult[dep].err);
            }
        });
    });

    return summary;
};

var slowestRegion = function(regions) {
    return Object.keys(regions).reduce(function(slowest, region) {
        return (!slowest || regions[region] > regions[slowest]) ? region : slowest;
    }, null);
};

/**
 * Starts a named stage. Names use '/' for nesting ('collect/calls').
 * @param since Optional {at, mem, cpu} to backdate the start, e.g. BOOT.
 * @returns An object whose end() closes the stage.
 */
var startStage = function(name, since) {
    if (!enabled) return noopStage;

    var mem = since ? since.mem : observe();
    var stage = {
        name: name,
        start: since ? since.at : now(),
        cpuStart: since ? since.cpu : process.cpuUsage(),
        memStart: mem,
        peak: {rss: mem.rss, heapUsed: mem.heapUsed}
    };
    stages.push(stage);
    openStages.push(stage);
    if (!since) log('stage', 'START ' + name + ' | ' + memSummary(mem));

    return {
        end: function() {
            if (stage.end !== undefined) return;
            stage.memEnd = observe();
            stage.end = now();
            stage.durationMs = stage.end - stage.start;
            var cpu = process.cpuUsage(stage.cpuStart);
            stage.cpuMs = (cpu.user + cpu.system) / 1000;
            openStages.splice(openStages.indexOf(stage), 1);
            log('stage', 'END   ' + name + ' ' + formatMs(stage.durationMs) +
                ' cpu=' + formatMs(stage.cpuMs) +
                ' | ' + memSummary(stage.memEnd) +
                ' heapΔ=' + signedMb(stage.memEnd.heapUsed - stage.memStart.heapUsed) +
                ' | peak ' + memSummary(stage.peak));
        }
    };
};

/**
 * Starts timing one collector call (Service:call) across all of its regions.
 * @param phase 'call' or 'postcall#N'
 * @param getResult Returns collection[service][call] once the call is done.
 */
var collectorStart = function(phase, service, call, getResult) {
    if (!enabled) return noopCollector;

    var run = {collector: service + ':' + call, phase: phase, start: now(), regions: {}};
    collectorRuns.push(run);
    running.collectors++;
    log('collector', 'START ' + run.collector + ' [' + phase + ']');

    return {
        // Wraps an async region iterator so that each region gets its own time.
        timeRegion: function(iterator) {
            return function(region, regionCb) {
                var start = now();
                iterator(region, function(err) {
                    run.regions[region] = round(now() - start);
                    regionCb(err);
                });
            };
        },
        end: function() {
            if (run.durationMs !== undefined) return;
            run.durationMs = now() - run.start;
            running.collectors--;
            Object.assign(run, summarizeResult(getResult && getResult()));

            var slowest = slowestRegion(run.regions);
            log('collector', 'DONE  ' + run.collector + ' [' + phase + '] ' + formatMs(run.durationMs) +
                ' regions=' + run.regionsCalled + ' items=' + run.items + ' errors=' + run.errors +
                (run.errors ? '(' + formatErrorCodes(run.errorCodes) + ')' : '') +
                (slowest ? ' slowest=' + slowest + '(' + formatMs(run.regions[slowest]) + ')' : '') +
                ' | ' + memSummary(observe()));
        }
    };
};

/**
 * Starts timing one plugin. end(err, results) takes the plugin's callback args.
 */
var pluginStart = function(key, plugin) {
    if (!enabled) return noopPlugin;

    var run = {plugin: key, title: plugin.title, category: plugin.category, start: now()};
    pluginRuns.push(run);
    running.plugins[key] = run;

    return {
        end: function(err, results) {
            if (run.durationMs !== undefined) return;
            run.durationMs = now() - run.start;
            delete running.plugins[key];

            results = Array.isArray(results) ? results : [];
            run.results = results.length;
            run.status = {OK: 0, WARN: 0, FAIL: 0, UNKNOWN: 0};
            results.forEach(function(result) {
                run.status[STATUS_WORDS[result.status] || 'UNKNOWN']++;
            });
            if (err) run.error = String(err);

            log('plugin', 'DONE  ' + key + ' (' + plugin.title + ') ' + formatMs(run.durationMs) +
                ' results=' + run.results +
                ' OK=' + run.status.OK + ' WARN=' + run.status.WARN +
                ' FAIL=' + run.status.FAIL + ' UNKNOWN=' + run.status.UNKNOWN +
                (err ? ' ERROR=' + run.error : '') +
                ' | ' + memSummary(observe()));
        }
    };
};

// Times every request made by any aws-sdk (v2) client, the collectors'
// override files included. 'validate' is the first event of a request and
// 'complete' the last, so the time includes signing and the SDK's own retries.
var instrumentAws = function(AWS) {
    if (!enabled || awsInstrumented) return;
    awsInstrumented = true;

    AWS.events.on('validate', function(request) {
        request._profileStart = now();
        running.awsRequests++;
    });

    AWS.events.on('complete', function(response) {
        // A profiler bug must never fail a scan request.
        try {
            var request = response.request;
            var service = request.service;
            var key = ((service.api && service.api.serviceId) || service.serviceIdentifier) + ':' + request.operation;
            var region = (service.config && service.config.region) || 'global';
            var ms = 0;
            if (request._profileStart !== undefined) {
                ms = now() - request._profileStart;
                running.awsRequests--;
            }
            awsRequestsDone++;

            var op = awsOperations[key];
            if (!op) op = awsOperations[key] = {operation: key, requests: 0, totalMs: 0, maxMs: 0, errors: 0, retries: 0, errorCodes: {}, regions: {}};
            op.requests++;
            op.totalMs += ms;
            op.maxMs = Math.max(op.maxMs, ms);
            op.retries += response.retryCount || 0;
            if (response.error) {
                op.errors++;
                countErrorCode(op.errorCodes, response.error);
            }
            if (!op.regions[region]) op.regions[region] = {requests: 0, totalMs: 0};
            op.regions[region].requests++;
            op.regions[region].totalMs += ms;
        } catch (e) {
            // ignore
        }
    });
};

/**
 * Turns profiling on and records the 'startup' stage (module loading up to now).
 * @param opts {output: path to write the JSON profile to}
 */
var enable = function(opts) {
    if (enabled) return;
    enabled = true;
    options = opts || {};

    startStage('startup', BOOT).end();

    var sampler = setInterval(function() {
        var mem = observe();
        memoryTimeline.push({t: sinceBoot(), rss: mem.rss, heapUsed: mem.heapUsed});
    }, SAMPLE_INTERVAL_MS);

    var heartbeat = setInterval(function() {
        var current = openStages.length ? openStages[openStages.length - 1].name : '-';
        var pluginsRunning = Object.keys(running.plugins).length;
        log('heartbeat', 'stage=' + current +
            ' | collectors running=' + running.collectors + ' done=' + (collectorRuns.length - running.collectors) +
            ' | plugins running=' + pluginsRunning + ' done=' + (pluginRuns.length - pluginsRunning) +
            ' | aws requests in-flight=' + running.awsRequests + ' done=' + awsRequestsDone +
            ' | ' + memSummary(observe()));
    }, HEARTBEAT_INTERVAL_MS);

    // Neither timer may keep the process alive once the scan is done.
    sampler.unref();
    heartbeat.unref();
    timers.push(sampler, heartbeat);
};

// Serialized size of every collection[service][call], one entry at a time so
// that the largest string held at once is a single call's data.
var collectionSizes = function(collection) {
    var stage = startStage('profile/collection-size');
    var sizes = [];
    Object.keys(collection || {}).forEach(function(service) {
        Object.keys(collection[service] || {}).forEach(function(call) {
            var bytes;
            try {
                bytes = Buffer.byteLength(stringify(collection[service][call]));
            } catch (e) {
                bytes = -1;
            }
            sizes.push({collector: service + ':' + call, bytes: bytes});
        });
    });
    stage.end();
    return sizes.sort(function(a, b) { return b.bytes - a.bytes; });
};

// Prints rows as aligned columns: the first left-aligned, the rest right-aligned.
var printTable = function(title, headers, rows) {
    console.log('\n' + title);
    if (!rows.length) return console.log('  (none)');
    var widths = headers.map(function(header, i) {
        return rows.reduce(function(width, row) {
            return Math.max(width, String(row[i]).length);
        }, header.length);
    });
    var line = function(cells) {
        return '  ' + cells.map(function(cell, i) {
            return i === 0 ? String(cell).padEnd(widths[i]) : String(cell).padStart(widths[i]);
        }).join('  ');
    };
    console.log(line(headers));
    rows.forEach(function(row) { console.log(line(row)); });
};

var top = function(list, field) {
    return list.slice().sort(function(a, b) { return b[field] - a[field]; }).slice(0, TOP_N);
};

/**
 * Prints the profile summary and, with the output option, writes the full
 * profile as JSON. Call once, when the scan is done.
 * @param collection The collection, for per-call data sizes. Optional.
 */
var report = function(collection) {
    if (!enabled) return;
    timers.forEach(clearInterval);

    var sizes = collection ? collectionSizes(collection) : [];
    var totalMs = sinceBoot();
    var finalMem = observe();
    var totalCpu = process.cpuUsage(BOOT.cpu);
    var awsOps = Object.keys(awsOperations).map(function(key) { return awsOperations[key]; });
    var finishedCollectors = collectorRuns.filter(function(run) { return run.durationMs !== undefined; });
    var finishedPlugins = pluginRuns.filter(function(run) { return run.durationMs !== undefined; });

    console.log('\n[PROFILE] ======================== Scan profile ========================');

    printTable('Stages (wall time; % of total; memory at end of stage, heap change and peak during it)',
        ['stage', 'start', 'time', '%', 'cpu', 'rss', 'heap', 'heapΔ', 'peak rss', 'peak heap'],
        stages.map(function(stage) {
            var depth = stage.name.split('/').length - 1;
            var done = stage.durationMs !== undefined;
            return [
                '  '.repeat(depth) + stage.name,
                '+' + (sinceBoot(stage.start) / 1000).toFixed(1) + 's',
                done ? formatMs(stage.durationMs) : 'unfinished',
                done ? (stage.durationMs / totalMs * 100).toFixed(1) + '%' : '-',
                done ? formatMs(stage.cpuMs) : '-',
                done ? mb(stage.memEnd.rss) : '-',
                done ? mb(stage.memEnd.heapUsed) : '-',
                done ? signedMb(stage.memEnd.heapUsed - stage.memStart.heapUsed) : '-',
                mb(stage.peak.rss),
                mb(stage.peak.heapUsed)
            ];
        }));

    printTable('Top ' + TOP_N + ' slowest collectors (wall time across all regions)',
        ['collector', 'phase', 'time', 'regions', 'items', 'errors', 'slowest region'],
        top(finishedCollectors, 'durationMs').map(function(run) {
            var slowest = slowestRegion(run.regions);
            return [run.collector, run.phase, formatMs(run.durationMs), run.regionsCalled, run.items,
                run.errors ? run.errors + ' ' + formatErrorCodes(run.errorCodes) : 0,
                slowest ? slowest + ' ' + formatMs(run.regions[slowest]) : '-'];
        }));

    printTable('Top ' + TOP_N + ' AWS operations by total request time',
        ['operation', 'requests', 'total', 'avg', 'max', 'errors', 'retries'],
        top(awsOps, 'totalMs').map(function(op) {
            return [op.operation, op.requests, formatMs(op.totalMs), formatMs(op.totalMs / op.requests),
                formatMs(op.maxMs), op.errors ? op.errors + ' ' + formatErrorCodes(op.errorCodes) : 0, op.retries];
        }));

    printTable('Top ' + TOP_N + ' slowest plugins',
        ['plugin', 'category', 'time', 'results', 'FAIL', 'WARN'],
        top(finishedPlugins, 'durationMs').map(function(run) {
            return [run.plugin, run.category, formatMs(run.durationMs), run.results, run.status.FAIL, run.status.WARN];
        }));

    printTable('Top ' + TOP_N + ' largest collection entries (serialized size)',
        ['collector', 'size'],
        sizes.slice(0, TOP_N).map(function(size) { return [size.collector, mb(size.bytes)]; }));

    var unfinishedCollectors = collectorRuns.length - finishedCollectors.length;
    var unfinishedPlugins = Object.keys(running.plugins);
    var awsRequests = awsOps.reduce(function(sum, op) { return sum + op.requests; }, 0);
    var awsErrors = awsOps.reduce(function(sum, op) { return sum + op.errors; }, 0);
    var collectionBytes = sizes.reduce(function(sum, size) { return sum + Math.max(size.bytes, 0); }, 0);

    console.log('\nTotals');
    console.log('  wall time:   ' + formatMs(totalMs) + ' (cpu ' + formatMs((totalCpu.user + totalCpu.system) / 1000) + ')');
    console.log('  collectors:  ' + collectorRuns.length + ' run' + (unfinishedCollectors ? ', ' + unfinishedCollectors + ' never finished' : ''));
    console.log('  aws calls:   ' + awsRequests + ' requests, ' + awsErrors + ' errors');
    console.log('  plugins:     ' + pluginRuns.length + ' run' + (unfinishedPlugins.length ? ', never finished: ' + unfinishedPlugins.join(', ') : ''));
    console.log('  collection:  ' + mb(collectionBytes) + ' serialized');
    console.log('  memory:      peak ' + memSummary(peak) + ' | final ' + memSummary(finalMem));

    if (options.output) {
        var profile = {
            generatedAt: new Date().toISOString(),
            node: process.version,
            totalMs: round(totalMs),
            cpuMs: round((totalCpu.user + totalCpu.system) / 1000),
            memory: {peak: peak, final: finalMem, timeline: memoryTimeline},
            stages: stages.map(function(stage) {
                return {
                    name: stage.name,
                    startMs: sinceBoot(stage.start),
                    durationMs: stage.durationMs === undefined ? null : round(stage.durationMs),
                    cpuMs: stage.cpuMs === undefined ? null : round(stage.cpuMs),
                    memStart: stage.memStart,
                    memEnd: stage.memEnd || null,
                    peak: stage.peak
                };
            }),
            collectors: collectorRuns.map(function(run) {
                return Object.assign({}, run, {
                    start: undefined,
                    startMs: sinceBoot(run.start),
                    durationMs: run.durationMs === undefined ? null : round(run.durationMs)
                });
            }),
            awsOperations: awsOps,
            plugins: pluginRuns.map(function(run) {
                return Object.assign({}, run, {
                    start: undefined,
                    startMs: sinceBoot(run.start),
                    durationMs: run.durationMs === undefined ? null : round(run.durationMs)
                });
            }),
            collectionSizes: sizes
        };
        try {
            fs.writeFileSync(options.output, JSON.stringify(profile, null, 2));
            console.log('  profile:     written to ' + options.output);
        } catch (e) {
            console.log('  profile:     could not be written to ' + options.output + ': ' + e.message);
        }
    }
    console.log('[PROFILE] =================================================================\n');
};

module.exports = {
    BOOT: BOOT,
    enable: enable,
    isEnabled: function() { return enabled; },
    startStage: startStage,
    collectorStart: collectorStart,
    pluginStart: pluginStart,
    instrumentAws: instrumentAws,
    report: report
};
