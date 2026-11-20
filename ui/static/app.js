let form, targetInput, useCacheInput, shallowCloneInput, statusEl;
let summaryEl, tableBody, dependencyTreeEl, reportsLinksEl;
let monitorTableBody, monitorStatusEl, refreshMonitorBtn;
let datasetTableBody, refreshDatasetBtn, scanAllActiveBtn, populationActionStatus;
let dashTotalRepositories, dashTotalPackages, dashTotalScans, dashTotalVulns;
let refreshSummaryBtn, summaryStatusEl, severitySummaryEl;
let topRepositoriesTableBody, commonPackagesTableBody;
let latestScanTableBody, historyScanTableBody, historyMonitorTableBody;
let healthActiveCount, healthInactiveCount, healthMonitorCount, lastUpdatedText;
let addTargetForm, addTargetStatus, targetSearchInput, targetFilterSelect;
let importFileForm, importFileInput, importJsonTextForm, importJsonText, importStatus;
let importHistoryTableBody, importHistoryShell, importHistoryEmpty;
let summaryActiveCount, summaryInactiveCount, summarySourceCount, summaryTypeCount;
let summaryBySource, summaryByType;
let refreshAnalyticsBtn, reloadAnalyticsFrameBtn, analyticsFrame, analyticsStatus;
let timelineTargetSelect, refreshTimelineBtn, timelineStatusEl, timelineChartEl;
let timelineEventsEl, timelineDetailType, timelineDetailTableHead, timelineDetailTableBody;
let timelineCurrentCount, timelineNewCount, timelineResolvedCount;
let timelinePersistentCount, timelineUpdateCount, timelineTrendBadge;
let lifecycleOpenCount, lifecycleNewCount, lifecyclePersistentCount;
let lifecycleReintroducedCount, lifecycleResolvedCount, lifecycleFixCount;
let lifecycleOldCount, lifecycleResolutionAverage, lifecycleHistoryNote;
let lifecycleStatusFilter, lifecycleSeverityFilter, lifecycleFixFilter;
let lifecyclePriorityTableBody;
let batchScanForm, batchTargetInput, batchTargetCount, batchUseCacheInput;
let batchShallowCloneInput, batchScanButton, batchStatusEl, batchProgressShell;
let batchProgressText, batchCurrentTarget, batchProgressBar, batchResultsShell, batchResultsTableBody;
let schedulerConfigForm, schedulerInterval, schedulerEnabled, schedulerRunNow;
let schedulerRefresh, schedulerStateBadge, schedulerStatusMessage, sidebarSchedulerStatus;
let schedulerActiveCount, schedulerLastRun, schedulerNextRun, schedulerSuccessCount;
let schedulerUpcoming, schedulerHistoryTableBody;
let schedulerTargetForm, schedulerTargetUrl, schedulerTargetMessage, schedulerTargetList;
let riskSettingsForm, riskImpactWeight, riskExploitationWeight, riskExposureWeight;
let riskPersistenceWeight, riskRemediationWeight, riskSettingsTotal, riskSettingsMessage;
let refreshAlertsBtn, alertsStatusEl, alertsTableBody;
let alertsOpenCount, alertsCriticalCount, alertsHighCount, alertsReviewedCount, alertsNotReviewedCount, alertsResolvedCount;
let alertsRiskCriticalCount, alertsRiskHighCount;
let alertsActNowCount, alertsReviewSoonCount, alertsMonitorCount, alertsCompletedCount, alertsOverdueCount;
let alertsRepositoryFilter, alertsTypeFilter, alertsPriorityFilter, alertsStateFilter, alertsReviewFilter, alertsQueueFilter, alertsSearch;
let intelligenceOverlay, intelligencePanel, intelligenceClose, intelligenceStatus, intelligenceContent;

window._datasetRows = [];
window._monitorRows = [];
window._latestScanRows = [];
window._importHistory = [];
window._timelineData = null;
window._batchJobId = null;
window._batchPollTimer = null;
window._alertsData = [];

function initElements() {
  form = document.getElementById("scan-form");
  targetInput = document.getElementById("target-input");
  useCacheInput = document.getElementById("use-cache");
  shallowCloneInput = document.getElementById("shallow-clone");
  statusEl = document.getElementById("status");

  summaryEl = document.getElementById("summary");
  tableBody = document.querySelector("#vulnerability-table tbody");
  dependencyTreeEl = document.getElementById("dependency-tree");
  reportsLinksEl = document.getElementById("reports-links");

  monitorTableBody = document.querySelector("#monitor-table tbody");
  monitorStatusEl = document.getElementById("monitor-status");
  refreshMonitorBtn = document.getElementById("refresh-monitor");

  datasetTableBody = document.querySelector("#dataset-table tbody");
  refreshDatasetBtn = document.getElementById("refresh-dataset");
  scanAllActiveBtn = document.getElementById("scan-all-active");
  populationActionStatus = document.getElementById("population-action-status");

  dashTotalRepositories = document.getElementById("dash-total-repositories");
  dashTotalPackages = document.getElementById("dash-total-packages");
  dashTotalScans = document.getElementById("dash-total-scans");
  dashTotalVulns = document.getElementById("dash-total-vulns");
  refreshSummaryBtn = document.getElementById("refresh-summary");
  summaryStatusEl = document.getElementById("summary-status");
  severitySummaryEl = document.getElementById("severity-summary");
  topRepositoriesTableBody = document.querySelector("#top-repositories-table tbody");
  commonPackagesTableBody = document.querySelector("#common-packages-table tbody");

  latestScanTableBody = document.querySelector("#latest-scan-table tbody");
  historyScanTableBody = document.querySelector("#history-scan-table tbody");
  historyMonitorTableBody = document.querySelector("#history-monitor-table tbody");

  healthActiveCount = document.getElementById("health-active-count");
  healthInactiveCount = document.getElementById("health-inactive-count");
  healthMonitorCount = document.getElementById("health-monitor-count");
  lastUpdatedText = document.getElementById("last-updated-text");

  addTargetForm = document.getElementById("add-target-form");
  addTargetStatus = document.getElementById("add-target-status");
  targetSearchInput = document.getElementById("target-search");
  targetFilterSelect = document.getElementById("target-filter");

  importFileForm = document.getElementById("import-file-form");
  importFileInput = document.getElementById("import-file");
  importJsonTextForm = document.getElementById("import-json-text-form");
  importJsonText = document.getElementById("import-json-text");
  importStatus = document.getElementById("import-status");

  importHistoryTableBody = document.querySelector("#import-history-table tbody");
  importHistoryShell = document.getElementById("import-history-shell");
  importHistoryEmpty = document.getElementById("import-history-empty");

  summaryActiveCount = document.getElementById("summary-active-count");
  summaryInactiveCount = document.getElementById("summary-inactive-count");
  summarySourceCount = document.getElementById("summary-source-count");
  summaryTypeCount = document.getElementById("summary-type-count");
  summaryBySource = document.getElementById("summary-by-source");
  summaryByType = document.getElementById("summary-by-type");

  refreshAnalyticsBtn = document.getElementById("refresh-analytics");
  reloadAnalyticsFrameBtn = document.getElementById("reload-analytics-frame");
  analyticsFrame = document.getElementById("analytics-frame");
  analyticsStatus = document.getElementById("analytics-status");

  timelineTargetSelect = document.getElementById("timeline-target-select");
  refreshTimelineBtn = document.getElementById("refresh-timeline");
  timelineStatusEl = document.getElementById("timeline-status");
  timelineChartEl = document.getElementById("timeline-chart");
  timelineEventsEl = document.getElementById("timeline-events");
  timelineDetailType = document.getElementById("timeline-detail-type");
  timelineDetailTableHead = document.querySelector("#timeline-detail-table thead");
  timelineDetailTableBody = document.querySelector("#timeline-detail-table tbody");
  timelineCurrentCount = document.getElementById("timeline-current-count");
  timelineNewCount = document.getElementById("timeline-new-count");
  timelineResolvedCount = document.getElementById("timeline-resolved-count");
  timelinePersistentCount = document.getElementById("timeline-persistent-count");
  timelineUpdateCount = document.getElementById("timeline-update-count");
  timelineTrendBadge = document.getElementById("timeline-trend-badge");
  lifecycleOpenCount = document.getElementById("lifecycle-open-count");
  lifecycleNewCount = document.getElementById("lifecycle-new-count");
  lifecyclePersistentCount = document.getElementById("lifecycle-persistent-count");
  lifecycleReintroducedCount = document.getElementById("lifecycle-reintroduced-count");
  lifecycleResolvedCount = document.getElementById("lifecycle-resolved-count");
  lifecycleFixCount = document.getElementById("lifecycle-fix-count");
  lifecycleOldCount = document.getElementById("lifecycle-old-count");
  lifecycleResolutionAverage = document.getElementById("lifecycle-resolution-average");
  lifecycleHistoryNote = document.getElementById("lifecycle-history-note");
  lifecycleStatusFilter = document.getElementById("lifecycle-status-filter");
  lifecycleSeverityFilter = document.getElementById("lifecycle-severity-filter");
  lifecycleFixFilter = document.getElementById("lifecycle-fix-filter");
  lifecyclePriorityTableBody = document.querySelector("#lifecycle-priority-table tbody");

  batchScanForm = document.getElementById("batch-scan-form");
  batchTargetInput = document.getElementById("batch-target-input");
  batchTargetCount = document.getElementById("batch-target-count");
  batchUseCacheInput = document.getElementById("batch-use-cache");
  batchShallowCloneInput = document.getElementById("batch-shallow-clone");
  batchScanButton = document.getElementById("batch-scan-button");
  batchStatusEl = document.getElementById("batch-status");
  batchProgressShell = document.getElementById("batch-progress-shell");
  batchProgressText = document.getElementById("batch-progress-text");
  batchCurrentTarget = document.getElementById("batch-current-target");
  batchProgressBar = document.getElementById("batch-progress-bar");
  batchResultsShell = document.getElementById("batch-results-shell");
  batchResultsTableBody = document.querySelector("#batch-results-table tbody");

  schedulerConfigForm = document.getElementById("scheduler-config-form");
  schedulerInterval = document.getElementById("scheduler-interval");
  schedulerEnabled = document.getElementById("scheduler-enabled");
  schedulerRunNow = document.getElementById("scheduler-run-now");
  schedulerRefresh = document.getElementById("refresh-scheduler");
  schedulerStateBadge = document.getElementById("scheduler-state-badge");
  schedulerStatusMessage = document.getElementById("scheduler-status-message");
  sidebarSchedulerStatus = document.getElementById("sidebar-scheduler-status");
  schedulerActiveCount = document.getElementById("scheduler-active-count");
  schedulerLastRun = document.getElementById("scheduler-last-run");
  schedulerNextRun = document.getElementById("scheduler-next-run");
  schedulerSuccessCount = document.getElementById("scheduler-success-count");
  schedulerUpcoming = document.getElementById("scheduler-upcoming");
  schedulerHistoryTableBody = document.querySelector("#scheduler-history-table tbody");
  schedulerTargetForm = document.getElementById("scheduler-target-form");
  schedulerTargetUrl = document.getElementById("scheduler-target-url");
  schedulerTargetMessage = document.getElementById("scheduler-target-message");
  schedulerTargetList = document.getElementById("scheduler-target-list");
  riskSettingsForm = document.getElementById("risk-settings-form");
  riskImpactWeight = document.getElementById("risk-impact-weight");
  riskExploitationWeight = document.getElementById("risk-exploitation-weight");
  riskExposureWeight = document.getElementById("risk-exposure-weight");
  riskPersistenceWeight = document.getElementById("risk-persistence-weight");
  riskRemediationWeight = document.getElementById("risk-remediation-weight");
  riskSettingsTotal = document.getElementById("risk-settings-total");
  riskSettingsMessage = document.getElementById("risk-settings-message");

  refreshAlertsBtn = document.getElementById("refresh-alerts");
  alertsStatusEl = document.getElementById("alerts-status");
  alertsTableBody = document.querySelector("#alerts-table tbody");
  alertsOpenCount = document.getElementById("alerts-open-count");
  alertsCriticalCount = document.getElementById("alerts-critical-count");
  alertsHighCount = document.getElementById("alerts-high-count");
  alertsReviewedCount = document.getElementById("alerts-reviewed-count");
  alertsNotReviewedCount = document.getElementById("alerts-not-reviewed-count");
  alertsResolvedCount = document.getElementById("alerts-resolved-count");
  alertsRiskCriticalCount = document.getElementById("alerts-risk-critical-count");
  alertsRiskHighCount = document.getElementById("alerts-risk-high-count");
  alertsActNowCount = document.getElementById("alerts-act-now-count");
  alertsReviewSoonCount = document.getElementById("alerts-review-soon-count");
  alertsMonitorCount = document.getElementById("alerts-monitor-count");
  alertsCompletedCount = document.getElementById("alerts-completed-count");
  alertsOverdueCount = document.getElementById("alerts-overdue-count");
  alertsRepositoryFilter = document.getElementById("alerts-repository-filter");
  alertsTypeFilter = document.getElementById("alerts-type-filter");
  alertsPriorityFilter = document.getElementById("alerts-priority-filter");
  alertsStateFilter = document.getElementById("alerts-state-filter");
  alertsReviewFilter = document.getElementById("alerts-review-filter");
  alertsQueueFilter = document.getElementById("alerts-queue-filter");
  alertsSearch = document.getElementById("alerts-search");
  intelligenceOverlay = document.getElementById("intelligence-overlay");
  intelligencePanel = document.getElementById("intelligence-panel");
  intelligenceClose = document.getElementById("close-intelligence");
  intelligenceStatus = document.getElementById("intelligence-status");
  intelligenceContent = document.getElementById("intelligence-content");
}

function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function formatDateTime(value) {
  if (!value) return "—";
  const normalized = String(value).replace(" ", "T");
  const date = new Date(normalized);
  if (isNaN(date.getTime())) return escapeHtml(value);
  return date.toLocaleString("en-US", {
    timeZone: "America/New_York",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "short"
  });
}

function severityClass(severity) {
  const key = String(severity || "none").toLowerCase();
  if (key === "critical") return "severity-critical";
  if (key === "high") return "severity-high";
  if (key === "medium") return "severity-medium";
  if (key === "low") return "severity-low";
  if (key === "negligible") return "severity-negligible";
  return "severity-none";
}

function getTargetStatusBadge(activeValue) {
  const isActive = String(activeValue) === "1";
  return isActive
    ? "<span class='status-pill status-active'>Active</span>"
    : "<span class='status-pill status-inactive'>Inactive</span>";
}

function updateLastUpdatedText() {
  if (!lastUpdatedText) return;
  const now = new Date();
  lastUpdatedText.textContent = "Updated " + now.toLocaleTimeString("en-US", {
    timeZone: "America/New_York",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    timeZoneName: "short"
  });
}

function switchPanel(panelId) {
  document.querySelectorAll(".panel-screen").forEach(function(panel) {
    panel.classList.add("hidden-panel");
    panel.classList.remove("active-panel");
  });

  document.querySelectorAll(".nav-item").forEach(function(btn) {
    btn.classList.remove("active");
  });

  const panel = document.getElementById(panelId);
  const nav = document.querySelector('.nav-item[data-panel="' + panelId + '"]');

  if (panel) {
    panel.classList.remove("hidden-panel");
    panel.classList.add("active-panel");
  }

  if (nav) {
    nav.classList.add("active");
  }
}

function setupSidebarNavigation() {
  document.querySelectorAll(".nav-item").forEach(function(button) {
    button.addEventListener("click", function() {
      const panelId = this.getAttribute("data-panel");
      if (panelId) {
        switchPanel(panelId);
        if (panelId === "timeline-panel" && !window._timelineData) {
          fetchTimelineTargets();
        }
        if (panelId === "timeline-panel") {
          fetchDatabaseSummary();
        }
        if (panelId === "scheduler-panel") {
          fetchSchedulerStatus();
        }
        if (panelId === "alerts-panel") {
          fetchAlerts();
        }
      }
    });
  });
}

function renderSummary(report) {
  const summary = report.summary || {};
  const scanId = escapeHtml(report.scan_id || "");
  const target = escapeHtml(report.target || "");
  const timestamp = formatDateTime(report.timestamp);
  const dbMessage = report.database_message || "";

  summaryEl.innerHTML =
    "<p><strong>Scan ID:</strong> " + scanId + "</p>" +
    "<p><strong>Target:</strong> " + target + "</p>" +
    "<p><strong>Timestamp:</strong> " + timestamp + "</p>" +
    "<div class='summary-grid'>" +
      "<div><strong>Total Packages:</strong><br>" + escapeHtml(summary.total_packages || 0) + "</div>" +
      "<div><strong>Total Vulnerabilities:</strong><br>" + escapeHtml(summary.total_vulnerabilities || 0) + "</div>" +
      "<div><strong>Level 1 Libraries:</strong><br>" + escapeHtml(summary.level_1_libraries || 0) + "</div>" +
      "<div><strong>Level 2 Libraries:</strong><br>" + escapeHtml(summary.level_2_libraries || 0) + "</div>" +
      "<div><strong>Critical:</strong><br>" + escapeHtml(summary.critical || 0) + "</div>" +
      "<div><strong>High:</strong><br>" + escapeHtml(summary.high || 0) + "</div>" +
      "<div><strong>Medium:</strong><br>" + escapeHtml(summary.medium || 0) + "</div>" +
      "<div><strong>Low:</strong><br>" + escapeHtml(summary.low || 0) + "</div>" +
      "<div><strong>Negligible:</strong><br>" + escapeHtml(summary.negligible || 0) + "</div>" +
    "</div>";

  const jsonName = scanId + ".json";
  const csvName = scanId + ".csv";

  reportsLinksEl.innerHTML =
    "<p>" +
      "<a href='/reports/" + encodeURIComponent(jsonName) + "' target='_blank'>Download JSON report</a>" +
      " | " +
      "<a href='/reports/" + encodeURIComponent(csvName) + "' target='_blank'>Download CSV report</a>" +
    "</p>" +
    (dbMessage
      ? "<div class='summary-box summary-box-inline'>" + escapeHtml(dbMessage) + "</div>"
      : "");
}

function renderTable(packages) {
  tableBody.innerHTML = "";

  if (!packages || packages.length === 0) {
    tableBody.innerHTML = "<tr><td colspan='6'>No packages found.</td></tr>";
    return;
  }

  for (let i = 0; i < packages.length; i++) {
    const pkg = packages[i];
    let vulnId = pkg.vulnerability_id || "None";
    const severity = pkg.severity || "None";
    const fixedVer = pkg.fixed_version || "N/A";

    if (vulnId === "None" || vulnId === "N/A") {
      let hasRealVuln = false;
      for (let j = 0; j < packages.length; j++) {
        if (
          packages[j].package === pkg.package &&
          packages[j].version === pkg.version &&
          packages[j].vulnerability_id &&
          packages[j].vulnerability_id !== "None" &&
          packages[j].vulnerability_id !== "N/A"
        ) {
          hasRealVuln = true;
          break;
        }
      }
      if (hasRealVuln) continue;
    }

    const row = document.createElement("tr");
    row.innerHTML =
      "<td>" + escapeHtml(pkg.package || "") + "</td>" +
      "<td>" + escapeHtml(pkg.version || "") + "</td>" +
      "<td>" + escapeHtml(pkg.type || "") + "</td>" +
      "<td>" + escapeHtml(vulnId) + "</td>" +
      "<td><span class='severity-pill " + severityClass(severity) + "'>" + escapeHtml(severity) + "</span></td>" +
      "<td>" + escapeHtml(fixedVer) + "</td>";
    tableBody.appendChild(row);
  }
}

function renderDependencyTree(tree) {
  dependencyTreeEl.innerHTML = "";

  if (!tree || tree.length === 0) {
    dependencyTreeEl.innerHTML = "<p>No dependency tree data available.</p>";
    return;
  }

  function buildTree(nodes) {
    const ul = document.createElement("ul");

    for (let i = 0; i < nodes.length; i++) {
      const li = document.createElement("li");
      li.textContent = nodes[i].name || "unknown";

      if (nodes[i].children && nodes[i].children.length) {
        li.appendChild(buildTree(nodes[i].children));
      }

      ul.appendChild(li);
    }

    return ul;
  }

  dependencyTreeEl.appendChild(buildTree(tree));
}

function renderPopulationSummary(rows) {
  const safeRows = rows || [];
  const activeCount = safeRows.filter(function(r) {
    return String(r.active) === "1";
  }).length;
  const inactiveCount = safeRows.length - activeCount;

  const sourceCounts = {};
  const typeCounts = {};

  safeRows.forEach(function(r) {
    const source = String(r.source_name || "unknown").trim() || "unknown";
    const type = String(r.target_type || "unknown").trim() || "unknown";
    sourceCounts[source] = (sourceCounts[source] || 0) + 1;
    typeCounts[type] = (typeCounts[type] || 0) + 1;
  });

  if (summaryActiveCount) summaryActiveCount.textContent = activeCount;
  if (summaryInactiveCount) summaryInactiveCount.textContent = inactiveCount;
  if (summarySourceCount) summarySourceCount.textContent = Object.keys(sourceCounts).length;
  if (summaryTypeCount) summaryTypeCount.textContent = Object.keys(typeCounts).length;

  function renderRankedList(container, entries, emptyMessage) {
    if (!container) return;

    container.innerHTML = "";

    if (!entries.length) {
      container.innerHTML = "<div class='muted'>" + emptyMessage + "</div>";
      return;
    }

    const topEntries = entries.slice(0, 5);

    topEntries.forEach(function(entry) {
      const item = document.createElement("div");
      item.className = "summary-row";

      const label = document.createElement("span");
      label.className = "summary-row-label";
      label.textContent = entry[0];

      const value = document.createElement("span");
      value.className = "summary-row-value";
      value.textContent = entry[1];

      item.appendChild(label);
      item.appendChild(value);
      container.appendChild(item);
    });

    if (entries.length > 5) {
      const more = document.createElement("div");
      more.className = "summary-more";
      more.textContent = "+" + (entries.length - 5) + " more";
      container.appendChild(more);
    }
  }

  const sourceEntries = Object.entries(sourceCounts).sort(function(a, b) {
    return b[1] - a[1];
  });

  const typeEntries = Object.entries(typeCounts).sort(function(a, b) {
    return b[1] - a[1];
  });

  renderRankedList(summaryBySource, sourceEntries, "No source data");
  renderRankedList(summaryByType, typeEntries, "No type data");
}

function renderImportHistory() {
  if (!importHistoryTableBody || !importHistoryShell || !importHistoryEmpty) return;

  importHistoryTableBody.innerHTML = "";

  if (!window._importHistory.length) {
    importHistoryShell.classList.add("hidden-panel");
    importHistoryEmpty.classList.remove("hidden-panel");
    return;
  }

  importHistoryShell.classList.remove("hidden-panel");
  importHistoryEmpty.classList.add("hidden-panel");

  window._importHistory.forEach(function(item) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      "<td>" + escapeHtml(item.time) + "</td>" +
      "<td>" + escapeHtml(item.mode) + "</td>" +
      "<td>" + escapeHtml(item.received) + "</td>" +
      "<td>" + escapeHtml(item.inserted) + "</td>" +
      "<td>" + escapeHtml(item.skipped_duplicates) + "</td>";
    importHistoryTableBody.appendChild(tr);
  });
}

function addImportHistoryEntry(mode, data) {
  const entry = {
    time: new Date().toLocaleString(),
    mode: mode,
    received: data.received || 0,
    inserted: data.inserted || 0,
    skipped_duplicates: data.skipped_duplicates || 0
  };

  window._importHistory.unshift(entry);
  window._importHistory = window._importHistory.slice(0, 10);
  renderImportHistory();
}

function renderDataset(rows) {
  datasetTableBody.innerHTML = "";

  if (!rows || rows.length === 0) {
    datasetTableBody.innerHTML = "<tr><td colspan='7'>No target rows found.</td></tr>";
    renderPopulationSummary([]);
    return;
  }

  renderPopulationSummary(rows);

  const searchText = (targetSearchInput ? targetSearchInput.value : "").trim().toLowerCase();
  const filterValue = targetFilterSelect ? targetFilterSelect.value : "all";

  const filtered = rows.filter(function(r) {
    const isActive = String(r.active) === "1";

    if (filterValue === "active" && !isActive) return false;
    if (filterValue === "inactive" && isActive) return false;

    const combined = [
      r.target_id,
      r.target_type,
      r.source_name,
      r.notes
    ].join(" ").toLowerCase();

    if (searchText && !combined.includes(searchText)) return false;

    return true;
  });

  if (filtered.length === 0) {
    datasetTableBody.innerHTML = "<tr><td colspan='7'>No matching targets found.</td></tr>";
    return;
  }

  filtered.forEach(function(r) {
    const tr = document.createElement("tr");
    const isActive = String(r.active) === "1";

    tr.innerHTML =
      "<td>" + escapeHtml(r.target_id || "") + "</td>" +
      "<td>" + escapeHtml(r.target_type || "") + "</td>" +
      "<td>" + escapeHtml(r.source_name || "") + "</td>" +
      "<td>" + getTargetStatusBadge(r.active) + "</td>" +
      "<td>" + formatDateTime(r.last_scan_time) + "</td>" +
      "<td>" + escapeHtml(r.notes || "") + "</td>" +
      "<td>" +
        "<div class='table-action-group'>" +
          "<button class='btn btn-small js-scan-target' data-target-pk='" + escapeHtml(r.target_pk) + "' data-target-id='" + escapeHtml(r.target_id) + "'>" +
            "Scan" +
          "</button>" +
          "<button class='btn btn-small js-toggle-status' data-target-pk='" + escapeHtml(r.target_pk) + "' data-next-active='" + (!isActive) + "'>" +
            (isActive ? "Disable" : "Enable") +
          "</button>" +
          "<button class='btn btn-small btn-danger js-delete-target' data-target-pk='" + escapeHtml(r.target_pk) + "'>" +
            "Delete" +
          "</button>" +
        "</div>" +
      "</td>";

    datasetTableBody.appendChild(tr);
  });

  bindTargetActionButtons();
}

function renderMonitorRowsToTable(rows, tbodyEl) {
  if (!tbodyEl) return;

  tbodyEl.innerHTML = "";

  if (!rows || rows.length === 0) {
    tbodyEl.innerHTML = "<tr><td colspan='10'>No monitor log rows found.</td></tr>";
    return;
  }

  rows.forEach(function(r) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      "<td>" + formatDateTime(r.scan_time) + "</td>" +
      "<td>" + escapeHtml(r.target_id || "") + "</td>" +
      "<td>" + escapeHtml(r.new_found ?? 0) + "</td>" +
      "<td>" + escapeHtml(r.resolved ?? 0) + "</td>" +
      "<td>" + escapeHtml(r.total_vulns ?? 0) + "</td>" +
      "<td>" + escapeHtml(r.critical ?? 0) + "</td>" +
      "<td>" + escapeHtml(r.high ?? 0) + "</td>" +
      "<td>" + escapeHtml(r.medium ?? 0) + "</td>" +
      "<td>" + escapeHtml(r.low ?? 0) + "</td>" +
      "<td>" + escapeHtml(r.latest_scan_id ?? "") + "</td>";

    tbodyEl.appendChild(tr);
  });
}

function renderLatestScans(rows) {
  [latestScanTableBody, historyScanTableBody].forEach(function(tbody) {
    if (!tbody) return;

    tbody.innerHTML = "";

    if (!rows || rows.length === 0) {
      tbody.innerHTML = "<tr><td colspan='3'>No scan rows found.</td></tr>";
      return;
    }

    rows.forEach(function(r) {
      const tr = document.createElement("tr");
      tr.innerHTML =
        "<td>" + escapeHtml(r.scan_id || "") + "</td>" +
        "<td>" + escapeHtml(r.target_id || "") + "</td>" +
        "<td>" + formatDateTime(r.scan_time) + "</td>";
      tbody.appendChild(tr);
    });
  });
}

function updateDashboard(datasetRows, monitorRows) {
  const safeDatasetRows = datasetRows || [];
  const safeMonitorRows = monitorRows || [];

  const activeCount = safeDatasetRows.filter(function(r) {
    return String(r.active) === "1";
  }).length;

  const inactiveCount = safeDatasetRows.length - activeCount;

  if (healthActiveCount) healthActiveCount.textContent = activeCount;
  if (healthInactiveCount) healthInactiveCount.textContent = inactiveCount;
  if (healthMonitorCount) healthMonitorCount.textContent = safeMonitorRows.length;
}

function setLoading(isLoading, message) {
  const button = document.getElementById("scan-button");
  if (button) {
    button.disabled = isLoading;
    button.textContent = isLoading ? "Scanning..." : "Run Scan";
  }

  if (statusEl) {
    statusEl.innerHTML = escapeHtml(message || "");
  }
}

function setPopulationActionStatus(message) {
  if (populationActionStatus) {
    populationActionStatus.textContent = message || "";
  }
}

function setAnalyticsStatus(message) {
  if (analyticsStatus) {
    analyticsStatus.textContent = message || "";
  }
}

function reloadAnalyticsFrame() {
  if (analyticsFrame) {
    analyticsFrame.src = "/static/dashboard_plus/dashboard_plus.html?v=" + Date.now();
  }
}

function refreshAnalytics() {
  setAnalyticsStatus("Refreshing analytics in background... please wait a little.");

  fetch("/api/analytics/refresh", {
    method: "POST",
    headers: { "Content-Type": "application/json" }
  })
    .then(function(res) {
      return res.json().then(function(data) {
        if (!res.ok) throw new Error(data.error || "Analytics refresh failed");
        return data;
      });
    })
    .then(function(data) {
      setAnalyticsStatus((data.message || "Analytics refresh started.") + " Reload the analytics view after 10-20 seconds.");
    })
    .catch(function(err) {
      console.error(err);
      setAnalyticsStatus("Error refreshing analytics: " + err.message);
    });
}

function fetchDataset() {
  return fetch("/api/db/targets")
    .then(function(res) {
      if (!res.ok) throw new Error("Failed to load targets");
      return res.json();
    })
    .then(function(data) {
      window._datasetRows = data.rows || [];
      renderDataset(window._datasetRows);
      updateDashboard(window._datasetRows, window._monitorRows);
      updateLastUpdatedText();
    })
    .catch(function(err) {
      console.error(err);
    });
}

function fetchLatestScans() {
  return fetch("/api/db/latest-scans")
    .then(function(res) {
      if (!res.ok) throw new Error("Failed to load latest scans");
      return res.json();
    })
    .then(function(data) {
      window._latestScanRows = data.rows || [];
      renderLatestScans(window._latestScanRows);
      updateLastUpdatedText();
    })
    .catch(function(err) {
      console.error(err);
    });
}

function fetchMonitorLog() {
  if (monitorStatusEl) {
    monitorStatusEl.textContent = "Loading monitoring data...";
  }

  return fetch("/api/db/monitor-log")
    .then(function(res) {
      if (!res.ok) throw new Error("Failed to load monitor log");
      return res.json();
    })
    .then(function(data) {
      window._monitorRows = data.rows || [];
      renderMonitorRowsToTable(window._monitorRows, monitorTableBody);
      renderMonitorRowsToTable(window._monitorRows, historyMonitorTableBody);
      updateDashboard(window._datasetRows, window._monitorRows);

      if (monitorStatusEl) {
        monitorStatusEl.textContent = "";
      }

      updateLastUpdatedText();
    })
    .catch(function(err) {
      console.error(err);
      if (monitorStatusEl) {
        monitorStatusEl.textContent = "Error loading monitoring data.";
      }
    });
}

function bindTargetActionButtons() {
  document.querySelectorAll(".js-scan-target").forEach(function(btn) {
    btn.addEventListener("click", function() {
      const targetPk = this.getAttribute("data-target-pk");
      const targetId = this.getAttribute("data-target-id") || "";

      setPopulationActionStatus("Scanning target: " + targetId + " ...");

      fetch("/api/db/targets/" + targetPk + "/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          useCache: true,
          shallowClone: true
        })
      })
        .then(function(res) {
          return res.json().then(function(data) {
            if (!res.ok) throw new Error(data.error || "Scan failed");
            return data;
          });
        })
        .then(function(data) {
          if (!data.report) {
            throw new Error("No report data received");
          }

          renderSummary(data.report);
          renderTable(data.report.packages || []);
          renderDependencyTree(data.report.dependency_tree || []);

          setPopulationActionStatus("Scan completed for: " + targetId + ". Analytics refresh started in background.");
          switchPanel("results-panel");

          fetchDataset();
          fetchLatestScans();
          fetchMonitorLog();
        })
        .catch(function(err) {
          console.error(err);
          setPopulationActionStatus("Error scanning target: " + err.message);
          alert("Scan failed: " + err.message);
        });
    });
  });

  document.querySelectorAll(".js-toggle-status").forEach(function(btn) {
    btn.addEventListener("click", function() {
      const targetPk = this.getAttribute("data-target-pk");
      const nextActive = this.getAttribute("data-next-active") === "true";

      fetch("/api/db/targets/" + targetPk + "/status", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ active: nextActive })
      })
        .then(function(res) {
          if (!res.ok) throw new Error("Failed to update target status");
          return res.json();
        })
        .then(function() {
          fetchDataset();
        })
        .catch(function(err) {
          console.error(err);
          alert("Could not update target status.");
        });
    });
  });

  document.querySelectorAll(".js-delete-target").forEach(function(btn) {
    btn.addEventListener("click", function() {
      const targetPk = this.getAttribute("data-target-pk");

      if (!confirm("Delete this target from initial population?")) {
        return;
      }

      fetch("/api/db/targets/" + targetPk, {
        method: "DELETE"
      })
        .then(function(res) {
          if (!res.ok) throw new Error("Failed to delete target");
          return res.json();
        })
        .then(function() {
          fetchDataset();
        })
        .catch(function(err) {
          console.error(err);
          alert("Could not delete target.");
        });
    });
  });
}

function setupAddTargetForm() {
  if (!addTargetForm) return;

  addTargetForm.addEventListener("submit", function(event) {
    event.preventDefault();

    const payload = {
      target_id: document.getElementById("new-target-id").value.trim(),
      target_type: document.getElementById("new-target-type").value.trim(),
      source_name: document.getElementById("new-source-name").value.trim(),
      notes: document.getElementById("new-notes").value.trim(),
      active: document.getElementById("new-active").checked
    };

    addTargetStatus.textContent = "Adding target...";

    fetch("/api/db/targets", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    })
      .then(function(res) {
        return res.json().then(function(data) {
          if (!res.ok) {
            throw new Error(data.error || "Failed to add target");
          }
          return data;
        });
      })
      .then(function(data) {
        addTargetStatus.textContent = data.message || "Target added successfully.";
        addTargetForm.reset();
        document.getElementById("new-active").checked = true;
        fetchDataset();
        switchPanel("population-panel");
      })
      .catch(function(err) {
        console.error(err);
        addTargetStatus.textContent = "Error: " + err.message;
      });
  });
}

function setupImportForms() {
  if (importFileForm) {
    importFileForm.addEventListener("submit", function(event) {
      event.preventDefault();

      const file = importFileInput.files && importFileInput.files[0];
      if (!file) {
        importStatus.textContent = "Please choose a CSV or JSON file.";
        return;
      }

      const formData = new FormData();
      formData.append("file", file);

      importStatus.textContent = "Importing file...";

      fetch("/api/db/targets/import", {
        method: "POST",
        body: formData
      })
        .then(function(res) {
          return res.json().then(function(data) {
            if (!res.ok) {
              const details = data.details ? "\n" + data.details.join("\n") : "";
              throw new Error((data.error || "Import failed") + details);
            }
            return data;
          });
        })
        .then(function(data) {
          importStatus.textContent =
            "Import completed.\n" +
            "Received: " + (data.received || 0) + "\n" +
            "Inserted: " + (data.inserted || 0) + "\n" +
            "Skipped duplicates: " + (data.skipped_duplicates || 0);

          addImportHistoryEntry("File Upload", data);
          importFileForm.reset();
          fetchDataset();
          switchPanel("population-panel");
        })
        .catch(function(err) {
          console.error(err);
          importStatus.textContent = "Error: " + err.message;
        });
    });
  }

  if (importJsonTextForm) {
    importJsonTextForm.addEventListener("submit", function(event) {
      event.preventDefault();

      const rawText = importJsonText.value.trim();
      if (!rawText) {
        importStatus.textContent = "Please paste JSON content first.";
        return;
      }

      const formData = new FormData();
      formData.append("content_type", "json");
      formData.append("raw_text", rawText);

      importStatus.textContent = "Importing pasted JSON...";

      fetch("/api/db/targets/import", {
        method: "POST",
        body: formData
      })
        .then(function(res) {
          return res.json().then(function(data) {
            if (!res.ok) {
              const details = data.details ? "\n" + data.details.join("\n") : "";
              throw new Error((data.error || "Import failed") + details);
            }
            return data;
          });
        })
        .then(function(data) {
          importStatus.textContent =
            "Import completed.\n" +
            "Received: " + (data.received || 0) + "\n" +
            "Inserted: " + (data.inserted || 0) + "\n" +
            "Skipped duplicates: " + (data.skipped_duplicates || 0);

          addImportHistoryEntry("Pasted JSON", data);
          importJsonTextForm.reset();
          fetchDataset();
          switchPanel("population-panel");
        })
        .catch(function(err) {
          console.error(err);
          importStatus.textContent = "Error: " + err.message;
        });
    });
  }
}

function setupTargetFilters() {
  if (targetSearchInput) {
    targetSearchInput.addEventListener("input", function() {
      renderDataset(window._datasetRows);
    });
  }

  if (targetFilterSelect) {
    targetFilterSelect.addEventListener("change", function() {
      renderDataset(window._datasetRows);
    });
  }
}

function setupScanAllActiveButton() {
  if (!scanAllActiveBtn) return;

  scanAllActiveBtn.addEventListener("click", function() {
    if (!confirm("Run scan for all active targets? Start with a small set first.")) {
      return;
    }

    setPopulationActionStatus("Scanning all active targets...");

    scanAllActiveBtn.disabled = true;
    scanAllActiveBtn.textContent = "Scanning...";

    fetch("/api/db/targets/scan-all-active", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        useCache: true,
        shallowClone: true
      })
    })
      .then(function(res) {
        return res.json().then(function(data) {
          if (!res.ok) throw new Error(data.error || "Scan all failed");
          return data;
        });
      })
      .then(function(data) {
        setPopulationActionStatus(
          "Scan-all completed. Success: " +
          (data.success_count || 0) +
          ", Failed: " +
          (data.failed_count || 0) +
          ". Analytics refresh started in background."
        );

        fetchDataset();
        fetchLatestScans();
        fetchMonitorLog();
        fetchDatabaseSummary();

        if (data.results && data.results.length > 0) {
          const firstSuccess = data.results.find(function(item) {
            return item.status === "success";
          });
          if (firstSuccess) {
            switchPanel("history-panel");
          }
        }
      })
      .catch(function(err) {
        console.error(err);
        setPopulationActionStatus("Error scanning active targets: " + err.message);
        alert("Scan-all failed: " + err.message);
      })
      .finally(function() {
        scanAllActiveBtn.disabled = false;
        scanAllActiveBtn.textContent = "Scan All Active Targets";
      });
  });
}

function setupAnalyticsControls() {
  if (refreshAnalyticsBtn) {
    refreshAnalyticsBtn.addEventListener("click", refreshAnalytics);
  }

  if (reloadAnalyticsFrameBtn) {
    reloadAnalyticsFrameBtn.addEventListener("click", reloadAnalyticsFrame);
  }
}

function setTimelineStatus(message, isError) {
  if (!timelineStatusEl) return;
  timelineStatusEl.textContent = message;
  timelineStatusEl.classList.toggle("status-error", Boolean(isError));
}

function fetchTimelineTargets() {
  if (!timelineTargetSelect) return;

  const previousValue = timelineTargetSelect.value;
  timelineTargetSelect.disabled = true;
  timelineTargetSelect.innerHTML = "<option value=''>Loading repositories...</option>";

  fetch("/api/db/vulnerability-timeline/targets")
    .then(function(res) {
      if (!res.ok) throw new Error("Could not load timeline repositories");
      return res.json();
    })
    .then(function(data) {
      const rows = data.rows || [];
      timelineTargetSelect.innerHTML = "";

      if (!rows.length) {
        timelineTargetSelect.innerHTML = "<option value=''>No scanned repositories are available</option>";
        setTimelineStatus("Run a repository scan to view current vulnerabilities.", false);
        return;
      }

      rows.forEach(function(row) {
        const option = document.createElement("option");
        option.value = row.target_id;
        option.textContent = row.target_id + " (" + row.scan_count + " scans)";
        timelineTargetSelect.appendChild(option);
      });

      const stillExists = rows.some(function(row) { return row.target_id === previousValue; });
      timelineTargetSelect.value = stillExists ? previousValue : rows[0].target_id;
      fetchVulnerabilityTimeline();
    })
    .catch(function(err) {
      console.error(err);
      timelineTargetSelect.innerHTML = "<option value=''>Could not load repositories</option>";
      setTimelineStatus("Error: " + err.message, true);
    })
    .finally(function() {
      timelineTargetSelect.disabled = false;
    });
}

function fetchVulnerabilityTimeline() {
  if (!timelineTargetSelect || !timelineTargetSelect.value) return;

  const target = timelineTargetSelect.value;
  setTimelineStatus("Loading scan comparisons...", false);
  if (refreshTimelineBtn) refreshTimelineBtn.disabled = true;

  fetch("/api/db/vulnerability-timeline?target=" + encodeURIComponent(target))
    .then(function(res) {
      return res.json().then(function(data) {
        if (!res.ok) throw new Error(data.error || "Timeline request failed");
        return data;
      });
    })
    .then(function(data) {
      window._timelineData = data;
      renderVulnerabilityTimeline(data);
      setTimelineStatus(
        data.scan_count > 1
          ? "Showing " + data.scan_count + " scans. Comparisons use consecutive scans of the selected repository."
          : "Showing the baseline scan. Run this repository again to create a scan comparison.",
        false
      );
      updateLastUpdatedText();
    })
    .catch(function(err) {
      console.error(err);
      window._timelineData = null;
      setTimelineStatus("Error: " + err.message, true);
    })
    .finally(function() {
      if (refreshTimelineBtn) refreshTimelineBtn.disabled = false;
    });
}

function renderVulnerabilityTimeline(data) {
  const summary = data.summary || {};
  const events = data.timeline || [];

  if (timelineCurrentCount) timelineCurrentCount.textContent = summary.current_vulnerabilities || 0;
  if (timelineNewCount) timelineNewCount.textContent = summary.new || 0;
  if (timelineResolvedCount) timelineResolvedCount.textContent = summary.resolved || 0;
  if (timelinePersistentCount) timelinePersistentCount.textContent = summary.persistent || 0;
  if (timelineUpdateCount) timelineUpdateCount.textContent = summary.package_updates || 0;

  renderTimelineTrend(summary.trend || "baseline");
  renderVulnerabilityLifecycle();
  renderTimelineChart(events);
  renderTimelineEvents(events);
  renderTimelineDetails();
}

function vulnerabilityReferenceUrl(identifier) {
  const value = String(identifier || "");
  if (/^CVE-/i.test(value)) {
    return "https://nvd.nist.gov/vuln/detail/" + encodeURIComponent(value);
  }
  if (/^GHSA-/i.test(value)) {
    return "https://github.com/advisories/" + encodeURIComponent(value);
  }
  return "";
}

function renderVulnerabilityLifecycle() {
  if (!lifecyclePriorityTableBody) return;

  const data = window._timelineData || {};
  const lifecycle = data.lifecycle || {};
  const summary = lifecycle.summary || {};
  const allRows = lifecycle.rows || [];

  if (lifecycleOpenCount) lifecycleOpenCount.textContent = summary.open || 0;
  if (lifecycleNewCount) lifecycleNewCount.textContent = summary.new || 0;
  if (lifecyclePersistentCount) lifecyclePersistentCount.textContent = summary.persistent || 0;
  if (lifecycleReintroducedCount) lifecycleReintroducedCount.textContent = summary.reintroduced || 0;
  if (lifecycleResolvedCount) lifecycleResolvedCount.textContent = summary.resolved || 0;
  if (lifecycleFixCount) lifecycleFixCount.textContent = summary.fix_available || 0;
  if (lifecycleOldCount) lifecycleOldCount.textContent = summary.older_than_30_days || 0;
  if (lifecycleResolutionAverage) {
    lifecycleResolutionAverage.textContent = summary.average_resolution_days == null
      ? "—" : summary.average_resolution_days + " days";
  }
  if (lifecycleHistoryNote) lifecycleHistoryNote.textContent = lifecycle.history_note || "Latest 30 scans";

  const statusFilter = lifecycleStatusFilter ? lifecycleStatusFilter.value : "all";
  const severityFilter = lifecycleSeverityFilter ? lifecycleSeverityFilter.value : "all";
  const fixFilter = lifecycleFixFilter ? lifecycleFixFilter.value : "all";
  const rows = allRows.filter(function(row) {
    const hasFix = Boolean(String(row.fixed_version || "").trim());
    return (statusFilter === "all" || row.status === statusFilter) &&
      (severityFilter === "all" || String(row.severity || "unknown").toLowerCase() === severityFilter) &&
      (fixFilter === "all" || (fixFilter === "available" ? hasFix : !hasFix));
  });

  lifecyclePriorityTableBody.innerHTML = "";
  if (!allRows.length) {
    lifecyclePriorityTableBody.innerHTML = "<tr><td colspan='10' class='empty-cell'>No vulnerability lifecycle records are available for this repository.</td></tr>";
    return;
  }
  if (!rows.length) {
    lifecyclePriorityTableBody.innerHTML = "<tr><td colspan='10' class='empty-cell'>No lifecycle records match the selected filters.</td></tr>";
    return;
  }

  const statusLabels = {
    new: "New",
    persistent: "Persistent",
    reintroduced: "Reintroduced",
    resolved: "Resolved",
    baseline: "Baseline"
  };
  const attentionLabels = {
    urgent: "Urgent",
    high: "High",
    medium: "Medium",
    low: "Low",
    resolved: "Resolved"
  };

  rows.forEach(function(row) {
    const referenceUrl = vulnerabilityReferenceUrl(row.vulnerability_id);
    const vulnerabilityCell = referenceUrl
      ? "<a class='vulnerability-reference' href='" + referenceUrl + "' target='_blank' rel='noopener noreferrer'>" + escapeHtml(row.vulnerability_id) + "</a>"
      : escapeHtml(row.vulnerability_id);
    const milestone = row.status === "resolved"
      ? (row.resolved_at ? "Resolved " + formatDateTime(row.resolved_at) : "Resolved")
      : (row.open_since ? formatDateTime(row.open_since) : "—");
    const duration = row.status === "resolved"
      ? (row.resolution_days == null ? "—" : row.resolution_days + " days to resolve")
      : (row.age_days == null ? "—" : row.age_days + " days open");
    const tr = document.createElement("tr");
    tr.innerHTML =
      "<td><span class='attention-pill attention-" + escapeHtml(row.attention) + "'>" + escapeHtml(attentionLabels[row.attention] || "Low") + "</span></td>" +
      "<td><strong>" + escapeHtml(row.package_name) + "</strong><small class='table-subtext'>" + escapeHtml(row.version || "N/A") + "</small></td>" +
      "<td>" + vulnerabilityCell + "</td>" +
      "<td><span class='severity-pill " + severityClass(row.severity) + "'>" + escapeHtml(row.severity || "Unknown") + "</span></td>" +
      "<td><span class='status-pill lifecycle-status-" + escapeHtml(row.status) + "'>" + escapeHtml(statusLabels[row.status] || row.status) + "</span></td>" +
      "<td>" + formatDateTime(row.first_seen) + "</td>" +
      "<td>" + milestone + "</td>" +
      "<td>" + escapeHtml(duration) + "</td>" +
      "<td>" + escapeHtml(row.scans_present || 0) + "</td>" +
      "<td>" + escapeHtml(row.fixed_version || "No known fix") + "</td>";
    lifecyclePriorityTableBody.appendChild(tr);
  });
}

function renderTimelineTrend(trend) {
  if (!timelineTrendBadge) return;
  const labels = {
    improved: "Security condition improved",
    worsened: "Security condition worsened",
    unchanged: "No security-score change",
    baseline: "Baseline scan"
  };
  timelineTrendBadge.className = "trend-badge trend-" + trend;
  timelineTrendBadge.textContent = labels[trend] || labels.baseline;
}

function renderTimelineChart(events) {
  if (!timelineChartEl) return;
  timelineChartEl.innerHTML = "";

  if (!events.length) {
    timelineChartEl.innerHTML = "<div class='empty-state'>No scans are available.</div>";
    return;
  }

  const maximum = Math.max.apply(null, events.map(function(event) {
    return parseInt(event.total_vulnerabilities || 0, 10);
  }).concat([1]));

  events.forEach(function(event) {
    const total = parseInt(event.total_vulnerabilities || 0, 10);
    const column = document.createElement("div");
    column.className = "timeline-chart-column";
    column.title = "Scan " + event.scan_id + ": " + total + " vulnerabilities";
    column.innerHTML =
      "<strong>" + total + "</strong>" +
      "<div class='timeline-chart-track'>" +
        "<span class='timeline-chart-bar trend-" + escapeHtml(event.trend || "baseline") +
        "' style='height:" + Math.max(5, Math.round((total / maximum) * 100)) + "%'></span>" +
      "</div>" +
      "<small>#" + escapeHtml(event.scan_id) + "</small>";
    timelineChartEl.appendChild(column);
  });
}

function renderTimelineEvents(events) {
  if (!timelineEventsEl) return;
  timelineEventsEl.innerHTML = "";

  if (!events.length) {
    timelineEventsEl.innerHTML = "<div class='empty-state'>No scans are available.</div>";
    return;
  }

  events.slice().reverse().forEach(function(event) {
    const item = document.createElement("article");
    item.className = "timeline-event trend-border-" + (event.trend || "baseline");

    let changeContent;
    if (event.baseline) {
      changeContent = "<span class='change-chip chip-baseline'>Baseline scan</span>";
    } else {
      changeContent =
        "<span class='change-chip chip-new'>+" + event.new_count + " new</span>" +
        "<span class='change-chip chip-resolved'>" + event.resolved_count + " resolved</span>" +
        "<span class='change-chip chip-open'>" + event.persistent_count + " still open</span>" +
        "<span class='change-chip chip-update'>" + event.package_update_count + " updates</span>";
    }

    const severity = event.severity || {};
    item.innerHTML =
      "<div class='timeline-event-dot'></div>" +
      "<div class='timeline-event-content'>" +
        "<div class='timeline-event-heading'>" +
          "<div><strong>Scan #" + escapeHtml(event.scan_id) + "</strong>" +
          "<span>" + formatDateTime(event.scan_time) + "</span></div>" +
          "<strong class='timeline-total'>" + escapeHtml(event.total_vulnerabilities) + " vulnerabilities</strong>" +
        "</div>" +
        "<div class='timeline-change-row'>" + changeContent + "</div>" +
        "<div class='timeline-severity-row'>" +
          "Critical " + (severity.critical || 0) + " · High " + (severity.high || 0) +
          " · Medium " + (severity.medium || 0) + " · Low " + (severity.low || 0) +
        "</div>" +
      "</div>";
    timelineEventsEl.appendChild(item);
  });
}

function renderTimelineDetails() {
  if (!timelineDetailTableHead || !timelineDetailTableBody) return;

  const data = window._timelineData;
  const events = data && data.timeline ? data.timeline : [];
  const latest = events.length ? events[events.length - 1] : null;
  const type = timelineDetailType ? timelineDetailType.value : "new";

  timelineDetailTableHead.innerHTML = "";
  timelineDetailTableBody.innerHTML = "";

  if (!latest || latest.baseline) {
    timelineDetailTableBody.innerHTML = "<tr><td>No previous scan is available for comparison.</td></tr>";
    return;
  }

  const rows = latest[type] || [];
  if (type === "package_updates") {
    timelineDetailTableHead.innerHTML =
      "<tr><th>Package</th><th>Previous Version</th><th>Current Version</th></tr>";
    if (!rows.length) {
      timelineDetailTableBody.innerHTML = "<tr><td colspan='3'>No vulnerable-package version changes detected.</td></tr>";
      return;
    }
    rows.forEach(function(row) {
      const tr = document.createElement("tr");
      tr.innerHTML =
        "<td>" + escapeHtml(row.package_name) + "</td>" +
        "<td>" + escapeHtml(row.previous_version) + "</td>" +
        "<td>" + escapeHtml(row.current_version) + "</td>";
      timelineDetailTableBody.appendChild(tr);
    });
    return;
  }

  timelineDetailTableHead.innerHTML =
    "<tr><th>Package</th><th>Version</th><th>Vulnerability</th><th>Severity</th><th>Fixed Version</th></tr>";

  if (!rows.length) {
    timelineDetailTableBody.innerHTML = "<tr><td colspan='5'>No " + escapeHtml(type) + " vulnerabilities in the latest comparison.</td></tr>";
    return;
  }

  rows.forEach(function(row) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      "<td>" + escapeHtml(row.package_name) + "</td>" +
      "<td>" + escapeHtml(row.version) + "</td>" +
      "<td>" + escapeHtml(row.vulnerability_id) + "</td>" +
      "<td><span class='severity-pill " + severityClass(row.severity) + "'>" + escapeHtml(row.severity) + "</span></td>" +
      "<td>" + escapeHtml(row.fixed_version || "N/A") + "</td>";
    timelineDetailTableBody.appendChild(tr);
  });
}

function setupTimelineControls() {
  if (timelineTargetSelect) {
    timelineTargetSelect.addEventListener("change", fetchVulnerabilityTimeline);
  }
  if (refreshTimelineBtn) {
    refreshTimelineBtn.addEventListener("click", fetchTimelineTargets);
  }
  if (timelineDetailType) {
    timelineDetailType.addEventListener("change", renderTimelineDetails);
  }
  [lifecycleStatusFilter, lifecycleSeverityFilter, lifecycleFixFilter]
    .filter(Boolean)
    .forEach(function(control) {
      control.addEventListener("change", renderVulnerabilityLifecycle);
    });
}

function getBatchTargets() {
  if (!batchTargetInput) return [];
  const seen = {};
  return batchTargetInput.value
    .split(/\r?\n/)
    .map(function(value) { return value.trim(); })
    .filter(function(value) {
      if (!value || seen[value]) return false;
      seen[value] = true;
      return true;
    });
}

function updateBatchTargetCount() {
  if (!batchTargetCount) return;
  const count = getBatchTargets().length;
  batchTargetCount.textContent = count + (count === 1 ? " repository" : " repositories");
  batchTargetCount.classList.toggle("count-error", count > 10);
}

function setBatchStatus(message, isError) {
  if (!batchStatusEl) return;
  batchStatusEl.textContent = message;
  batchStatusEl.classList.toggle("status-error", Boolean(isError));
}

function renderBatchResults(results) {
  if (!batchResultsTableBody || !batchResultsShell) return;
  batchResultsTableBody.innerHTML = "";

  if (!results || !results.length) {
    batchResultsShell.classList.add("hidden-panel");
    return;
  }

  batchResultsShell.classList.remove("hidden-panel");
  results.forEach(function(result) {
    const tr = document.createElement("tr");
    const success = result.status === "success";
    tr.innerHTML =
      "<td class='repository-cell' title='" + escapeHtml(result.target) + "'>" + escapeHtml(result.target) + "</td>" +
      "<td><span class='status-pill " + (success ? "status-active" : "status-inactive") + "'>" +
        escapeHtml(result.status) + "</span></td>" +
      "<td>" + escapeHtml(success ? result.total_packages : "—") + "</td>" +
      "<td>" + escapeHtml(success ? result.total_vulnerabilities : "—") + "</td>" +
      "<td class='batch-message-cell'>" + escapeHtml(success ? ("Scan " + result.scan_id) : (result.error || "Failed")) + "</td>";
    batchResultsTableBody.appendChild(tr);
  });
}

function renderBatchProgress(job) {
  const total = parseInt(job.total || 0, 10);
  const completed = parseInt(job.completed || 0, 10);
  const percentage = total ? Math.round((completed / total) * 100) : 0;

  if (batchProgressShell) batchProgressShell.classList.remove("hidden-panel");
  if (batchProgressText) batchProgressText.textContent = completed + " of " + total + " completed";
  if (batchCurrentTarget) {
    batchCurrentTarget.textContent = job.current_target
      ? "Scanning: " + job.current_target
      : (job.status === "completed" ? "Batch completed" : "Waiting to start");
  }
  if (batchProgressBar) batchProgressBar.style.width = percentage + "%";
  renderBatchResults(job.results || []);

  if (job.status === "completed") {
    setBatchStatus(
      "Batch completed. Successful: " + (job.success_count || 0) +
      ", Failed: " + (job.failed_count || 0) +
      ". Run the same batch again later to create timeline comparisons.",
      false
    );
    if (batchScanButton) {
      batchScanButton.disabled = false;
      batchScanButton.textContent = "Run This Batch Again";
    }
    window._batchJobId = null;
    if (window._batchPollTimer) {
      clearTimeout(window._batchPollTimer);
      window._batchPollTimer = null;
    }
    fetchLatestScans();
    fetchDatabaseSummary();
    window._timelineData = null;
    return;
  }

  setBatchStatus(
    "Batch scan is running in the background. Keep the application server open.",
    false
  );
}

function pollBatchJob() {
  if (!window._batchJobId) return;

  fetch("/api/scan/batch/" + encodeURIComponent(window._batchJobId))
    .then(function(res) {
      return res.json().then(function(data) {
        if (!res.ok) throw new Error(data.error || "Could not read batch status");
        return data;
      });
    })
    .then(function(job) {
      renderBatchProgress(job);
      if (job.status !== "completed") {
        window._batchPollTimer = setTimeout(pollBatchJob, 2000);
      }
    })
    .catch(function(err) {
      console.error(err);
      setBatchStatus("Error checking batch progress: " + err.message, true);
      if (batchScanButton) batchScanButton.disabled = false;
      window._batchJobId = null;
    });
}

function setupBatchScanForm() {
  if (!batchScanForm || !batchTargetInput) return;

  batchTargetInput.addEventListener("input", updateBatchTargetCount);
  updateBatchTargetCount();

  batchScanForm.addEventListener("submit", function(event) {
    event.preventDefault();
    const targets = getBatchTargets();

    if (!targets.length) {
      setBatchStatus("Enter at least one repository URL.", true);
      return;
    }
    if (targets.length > 10) {
      setBatchStatus("Only 10 repositories can be scanned in one batch.", true);
      return;
    }

    setBatchStatus("Starting batch scan...", false);
    if (batchScanButton) {
      batchScanButton.disabled = true;
      batchScanButton.textContent = "Batch Running...";
    }
    if (batchResultsTableBody) batchResultsTableBody.innerHTML = "";
    if (batchResultsShell) batchResultsShell.classList.add("hidden-panel");

    fetch("/api/scan/batch", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        targets: targets,
        useCache: batchUseCacheInput ? batchUseCacheInput.checked : true,
        shallowClone: batchShallowCloneInput ? batchShallowCloneInput.checked : true
      })
    })
      .then(function(res) {
        return res.json().then(function(data) {
          if (!res.ok) throw new Error(data.error || "Batch scan could not start");
          return data;
        });
      })
      .then(function(data) {
        window._batchJobId = data.job_id;
        renderBatchProgress({
          total: data.total,
          completed: 0,
          status: "queued",
          results: []
        });
        pollBatchJob();
      })
      .catch(function(err) {
        console.error(err);
        setBatchStatus("Error: " + err.message, true);
        if (batchScanButton) {
          batchScanButton.disabled = false;
          batchScanButton.textContent = "Start Batch Scan";
        }
      });
  });
}

function setSchedulerMessage(message, isError) {
  if (!schedulerStatusMessage) return;
  schedulerStatusMessage.textContent = message;
  schedulerStatusMessage.classList.toggle("status-error", Boolean(isError));
}

function schedulerStateLabel(config, cycleRunning) {
  if (cycleRunning || config.status === "running") return "Scanning now";
  return String(config.enabled) === "1" || config.enabled === true ? "Enabled" : "Stopped";
}

function renderSchedulerStatus(data) {
  const config = data.config || {};
  const history = data.history || [];
  const running = Boolean(data.cycle_running) || config.status === "running";
  const enabled = String(config.enabled) === "1" || config.enabled === true;
  const label = schedulerStateLabel(config, running);

  if (schedulerEnabled) schedulerEnabled.checked = enabled;
  if (schedulerInterval && config.interval_minutes) schedulerInterval.value = String(config.interval_minutes);
  if (schedulerActiveCount) schedulerActiveCount.textContent = data.active_target_count || 0;
  if (schedulerLastRun) schedulerLastRun.textContent = config.last_run_at ? formatDateTime(config.last_run_at) : "Not run";
  if (schedulerNextRun) schedulerNextRun.textContent = enabled && config.next_run_at
    ? formatDateTime(config.next_run_at) : "Not scheduled";
  if (schedulerSuccessCount) schedulerSuccessCount.textContent = history.filter(function(row) {
    return row.status === "success";
  }).length;
  if (sidebarSchedulerStatus) sidebarSchedulerStatus.textContent = label;
  if (schedulerStateBadge) {
    schedulerStateBadge.textContent = label;
    schedulerStateBadge.className = "trend-badge " +
      (running ? "trend-worsened" : (enabled ? "trend-improved" : "trend-baseline"));
  }
  if (schedulerStatusMessage) {
    if (running) {
      setSchedulerMessage("A scan cycle is running. Progress and results refresh automatically below.", false);
    } else if (enabled) {
      setSchedulerMessage("Scheduled scanning is enabled. Next run: " +
        (config.next_run_at ? formatDateTime(config.next_run_at) : "being calculated") + ".", false);
    } else {
      setSchedulerMessage("Scheduler is stopped. Add repositories, choose a frequency, then enable it.", false);
    }
  }
  if (schedulerRunNow) {
    schedulerRunNow.disabled = running || !(data.active_target_count > 0);
    schedulerRunNow.textContent = running ? "Scan Cycle Running..." : "Run Selected Repositories Now";
  }

  if (schedulerTargetList) {
    schedulerTargetList.innerHTML = "";
    const targets = data.active_targets || [];
    if (!targets.length) {
      schedulerTargetList.innerHTML = "<div class='empty-state'>No repositories selected for scheduled scanning.</div>";
    } else {
      targets.forEach(function(row) {
        const item = document.createElement("div");
        item.className = "scheduler-target-item";
        item.innerHTML =
          "<div><strong>" + escapeHtml(row.target_id) + "</strong>" +
          "<span>Last scan: " + (row.last_scan_time ? formatDateTime(row.last_scan_time) : "Not scanned yet") + "</span></div>" +
          "<button type='button' class='btn btn-secondary scheduler-remove-target' data-target-pk='" +
          escapeHtml(row.target_pk) + "'>Remove</button>";
        schedulerTargetList.appendChild(item);
      });
      schedulerTargetList.querySelectorAll(".scheduler-remove-target").forEach(function(button) {
        button.addEventListener("click", function() {
          const targetPk = this.getAttribute("data-target-pk");
          fetch("/api/scheduler/targets/" + encodeURIComponent(targetPk), { method: "DELETE" })
            .then(function(res) { return res.json().then(function(result) {
              if (!res.ok) throw new Error(result.error || "Could not remove repository");
              return result;
            }); })
            .then(function(result) {
              if (schedulerTargetMessage) schedulerTargetMessage.textContent = result.message;
              fetchSchedulerStatus();
            })
            .catch(function(err) {
              if (schedulerTargetMessage) schedulerTargetMessage.textContent = "Error: " + err.message;
            });
        });
      });
    }
  }

  if (schedulerUpcoming) {
    schedulerUpcoming.innerHTML = "";
    const upcoming = data.upcoming || [];
    if (!upcoming.length) {
      schedulerUpcoming.innerHTML = "<div class='empty-state'>No repositories selected. Add repositories in Scheduled Repositories above.</div>";
    } else {
      upcoming.forEach(function(row) {
        const item = document.createElement("article");
        item.className = "schedule-timeline-item";
        item.innerHTML =
          "<div class='schedule-order'>" + escapeHtml(row.order) + "</div>" +
          "<div><strong>" + escapeHtml(row.target_id) + "</strong>" +
          "<span>" + (enabled && row.scheduled_for ? formatDateTime(row.scheduled_for) : "Waiting for scheduler to be enabled") + "</span></div>" +
          "<span class='schedule-state'>" + (row.order === 1 ? "Runs first" : "Queued after previous repository") + "</span>";
        schedulerUpcoming.appendChild(item);
      });
    }
  }

  if (schedulerHistoryTableBody) {
    schedulerHistoryTableBody.innerHTML = "";
    if (!history.length) {
      schedulerHistoryTableBody.innerHTML = "<tr><td colspan='9' class='empty-cell'>No scheduled scans have run yet.</td></tr>";
    } else {
      history.forEach(function(row) {
        const tr = document.createElement("tr");
        const statusClass = row.status === "success" ? "status-active" :
          (row.status === "failed" ? "status-inactive" : "status-pending");
        tr.innerHTML =
          "<td class='repository-cell' title='" + escapeHtml(row.target_id) + "'>" + escapeHtml(row.target_id) + "</td>" +
          "<td>" + escapeHtml(row.trigger_type) + "</td>" +
          "<td>" + formatDateTime(row.started_at) + "</td>" +
          "<td>" + (row.finished_at ? formatDateTime(row.finished_at) : "In progress") + "</td>" +
          "<td><span class='status-pill " + statusClass + "'>" + escapeHtml(row.status) + "</span></td>" +
          "<td>" + escapeHtml(row.scan_id || "—") + "</td>" +
          "<td>" + escapeHtml(row.total_packages || 0) + "</td>" +
          "<td>" + escapeHtml(row.total_vulnerabilities || 0) + "</td>" +
          "<td class='error-detail' title='" + escapeHtml(row.error_message || "") + "'>" +
          escapeHtml(row.error_message || (row.status === "success" ? "Delivered to timeline" : "—")) + "</td>";
        schedulerHistoryTableBody.appendChild(tr);
      });
    }
  }
}

function fetchSchedulerStatus() {
  if (!schedulerStateBadge) return Promise.resolve();
  return fetch("/api/scheduler/status")
    .then(function(res) { return res.json().then(function(data) {
      if (!res.ok) throw new Error(data.error || "Could not load scheduler");
      return data;
    }); })
    .then(function(data) {
      renderSchedulerStatus(data);
      return data;
    })
    .catch(function(err) {
      console.error(err);
      setSchedulerMessage("Scheduler error: " + err.message, true);
    });
}

function riskSettingsPayload() {
  return {
    impact_weight: parseFloat(riskImpactWeight.value || "0"),
    exploitation_weight: parseFloat(riskExploitationWeight.value || "0"),
    exposure_weight: parseFloat(riskExposureWeight.value || "0"),
    persistence_weight: parseFloat(riskPersistenceWeight.value || "0"),
    remediation_weight: parseFloat(riskRemediationWeight.value || "0")
  };
}

function updateRiskSettingsTotal() {
  if (!riskSettingsTotal) return;
  const values = riskSettingsPayload();
  const total = Object.values(values).reduce(function(sum, value) {
    return sum + (isNaN(value) ? 0 : value);
  }, 0);
  riskSettingsTotal.textContent = "Total: " + total.toFixed(1).replace(/\.0$/, "");
  riskSettingsTotal.className = "trend-badge " + (Math.abs(total - 100) < 0.001 ? "trend-improved" : "trend-worsened");
}

function loadRiskSettings() {
  if (!riskSettingsForm) return Promise.resolve();
  return fetch("/api/risk-settings")
    .then(function(res) { return res.json().then(function(data) {
      if (!res.ok) throw new Error(data.error || "Could not load risk-score settings");
      return data;
    }); })
    .then(function(data) {
      const settings = data.settings || {};
      riskImpactWeight.value = settings.impact_weight;
      riskExploitationWeight.value = settings.exploitation_weight;
      riskExposureWeight.value = settings.exposure_weight;
      riskPersistenceWeight.value = settings.persistence_weight;
      riskRemediationWeight.value = settings.remediation_weight;
      updateRiskSettingsTotal();
      if (riskSettingsMessage) {
        riskSettingsMessage.textContent = "The current weights add to 100 and apply to newly calculated risk scores.";
        riskSettingsMessage.classList.remove("status-error");
      }
    })
    .catch(function(err) {
      if (riskSettingsMessage) {
        riskSettingsMessage.textContent = "Risk-score settings error: " + err.message;
        riskSettingsMessage.classList.add("status-error");
      }
    });
}

function setupSchedulerControls() {
  if (riskSettingsForm) {
    [riskImpactWeight, riskExploitationWeight, riskExposureWeight, riskPersistenceWeight, riskRemediationWeight].forEach(function(input) {
      input.addEventListener("input", updateRiskSettingsTotal);
    });
    riskSettingsForm.addEventListener("submit", function(event) {
      event.preventDefault();
      const values = riskSettingsPayload();
      const total = Object.values(values).reduce(function(sum, value) { return sum + value; }, 0);
      if (Object.values(values).some(function(value) { return isNaN(value) || value < 0 || value > 100; })) {
        if (riskSettingsMessage) riskSettingsMessage.textContent = "Enter a value from 0 to 100 for every risk-score weight.";
        return;
      }
      if (Math.abs(total - 100) >= 0.001) {
        if (riskSettingsMessage) riskSettingsMessage.textContent = "The five risk-score weights must add up to 100.";
        return;
      }
      if (riskSettingsMessage) riskSettingsMessage.textContent = "Saving risk-score settings...";
      fetch("/api/risk-settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(values)
      })
        .then(function(res) { return res.json().then(function(data) {
          if (!res.ok) throw new Error(data.error || "Could not save risk-score settings");
          return data;
        }); })
        .then(function(data) {
          if (riskSettingsMessage) {
            riskSettingsMessage.textContent = data.message;
            riskSettingsMessage.classList.remove("status-error");
          }
          loadRiskSettings();
        })
        .catch(function(err) {
          if (riskSettingsMessage) {
            riskSettingsMessage.textContent = "Error: " + err.message;
            riskSettingsMessage.classList.add("status-error");
          }
        });
    });
  }
  if (schedulerTargetForm) {
    schedulerTargetForm.addEventListener("submit", function(event) {
      event.preventDefault();
      const target = schedulerTargetUrl.value.trim();
      if (!target) return;
      if (schedulerTargetMessage) schedulerTargetMessage.textContent = "Adding repository...";
      fetch("/api/scheduler/targets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target_id: target })
      })
        .then(function(res) { return res.json().then(function(data) {
          if (!res.ok) throw new Error(data.error || "Could not add repository");
          return data;
        }); })
        .then(function(data) {
          schedulerTargetUrl.value = "";
          if (schedulerTargetMessage) schedulerTargetMessage.textContent = data.message;
          fetchSchedulerStatus();
          fetchDataset();
        })
        .catch(function(err) {
          if (schedulerTargetMessage) schedulerTargetMessage.textContent = "Error: " + err.message;
        });
    });
  }
  if (schedulerConfigForm) {
    schedulerConfigForm.addEventListener("submit", function(event) {
      event.preventDefault();
      setSchedulerMessage("Saving schedule...", false);
      fetch("/api/scheduler/config", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          enabled: schedulerEnabled.checked,
          interval_minutes: parseInt(schedulerInterval.value, 10)
        })
      })
        .then(function(res) { return res.json().then(function(data) {
          if (!res.ok) throw new Error(data.error || "Could not save schedule");
          return data;
        }); })
        .then(function(data) {
          setSchedulerMessage(data.message + ". Only repositories in the scheduled repository list will be scanned.", false);
          fetchSchedulerStatus();
        })
        .catch(function(err) { setSchedulerMessage("Error: " + err.message, true); });
    });
  }

  if (schedulerRunNow) {
    schedulerRunNow.addEventListener("click", function() {
      schedulerRunNow.disabled = true;
      setSchedulerMessage("Starting an immediate cycle for the selected repositories...", false);
      fetch("/api/scheduler/run-now", { method: "POST" })
        .then(function(res) { return res.json().then(function(data) {
          if (!res.ok) throw new Error(data.error || "Could not start scan cycle");
          return data;
        }); })
        .then(function(data) {
          setSchedulerMessage(data.message + ". Results will appear below automatically.", false);
          window.setTimeout(fetchSchedulerStatus, 500);
        })
        .catch(function(err) {
          setSchedulerMessage("Error: " + err.message, true);
          schedulerRunNow.disabled = false;
        });
    });
  }
  if (schedulerRefresh) schedulerRefresh.addEventListener("click", fetchSchedulerStatus);
}

const ALERT_TYPE_LABELS = {
  new_vulnerability: "New vulnerability",
  reintroduced_vulnerability: "Reintroduced",
  fix_available: "Fix available",
  long_open: "Long open",
  resolved_vulnerability: "Resolved",
  scan_failed: "Scan failure"
};

const ALERT_QUEUE_LABELS = {
  act_now: "Act Now",
  review_soon: "Review Soon",
  monitor: "Monitor",
  completed: "Completed"
};

function formatAlertDeadline(row) {
  if (row.action_queue === "completed") return "<span class='deadline-complete'>Completed</span>";
  const seconds = Number(row.remaining_seconds || 0);
  const absolute = Math.abs(seconds);
  const hours = Math.max(1, Math.ceil(absolute / 3600));
  const duration = hours >= 48 ? Math.ceil(hours / 24) + " days" : hours + " hours";
  const label = seconds < 0 ? "Overdue by " + duration : duration + " remaining";
  const className = seconds < 0 ? "deadline-overdue" : (seconds <= 86400 ? "deadline-near" : "deadline-normal");
  return "<span class='alert-deadline " + className + "'>" + escapeHtml(label) + "</span>" +
    "<small class='deadline-date'>Due " + formatDateTime(row.due_at) + "</small>";
}

function populateAlertRepositories(rows) {
  if (!alertsRepositoryFilter) return;
  const previous = alertsRepositoryFilter.value || "all";
  const repositories = Array.from(new Set((rows || []).map(function(row) {
    return String(row.repository || "").trim();
  }).filter(Boolean))).sort();
  alertsRepositoryFilter.innerHTML = "<option value='all'>All repositories</option>";
  repositories.forEach(function(repository) {
    const option = document.createElement("option");
    option.value = repository;
    option.textContent = repository;
    alertsRepositoryFilter.appendChild(option);
  });
  alertsRepositoryFilter.value = repositories.indexOf(previous) >= 0 ? previous : "all";
}

function renderAlerts() {
  if (!alertsTableBody) return;
  const repository = alertsRepositoryFilter ? alertsRepositoryFilter.value : "all";
  const type = alertsTypeFilter ? alertsTypeFilter.value : "all";
  const priority = alertsPriorityFilter ? alertsPriorityFilter.value : "all";
  const state = alertsStateFilter ? alertsStateFilter.value : "all";
  const reviewState = alertsReviewFilter ? alertsReviewFilter.value : "all";
  const queue = alertsQueueFilter ? alertsQueueFilter.value : "all";
  const search = alertsSearch ? alertsSearch.value.trim().toLowerCase() : "";

  const rows = (window._alertsData || []).filter(function(row) {
    if (repository !== "all" && row.repository !== repository) return false;
    if (type !== "all" && row.type !== type) return false;
    if (priority !== "all" && row.priority !== priority) return false;
    if (state !== "all" && row.status !== state) return false;
    if (reviewState === "reviewed" && !row.reviewed) return false;
    if (reviewState === "not_reviewed" && row.reviewed) return false;
    if (queue !== "all" && row.action_queue !== queue) return false;
    if (search) {
      const haystack = [row.repository, row.package, row.vulnerability_id, row.title, row.message]
        .map(function(value) { return String(value || "").toLowerCase(); }).join(" ");
      if (haystack.indexOf(search) === -1) return false;
    }
    return true;
  });

  alertsTableBody.innerHTML = "";
  if (!rows.length) {
    alertsTableBody.innerHTML = "<tr><td colspan='9' class='empty-cell'>No alerts match the selected filters.</td></tr>";
    return;
  }

  rows.forEach(function(row) {
    const tr = document.createElement("tr");
    const packageText = row.package
      ? escapeHtml(row.package) + (row.version ? " <span class='muted'>" + escapeHtml(row.version) + "</span>" : "")
      : "—";
    const vulnerabilityText = row.vulnerability_id
      ? "<div class='alert-vulnerability-id'>" + escapeHtml(row.vulnerability_id) + "</div>" : "";
    const reviewedAt = row.reviewed_at ? "<small>Reviewed " + formatDateTime(row.reviewed_at) + "</small>" : "<small>Not reviewed</small>";
    const reviewAction = "<label class='alert-review-control'>" +
      "<input type='checkbox' class='alert-review-checkbox' data-alert-key='" + escapeHtml(row.key) + "'" +
      (row.reviewed ? " checked" : "") + (row.status === "resolved" ? " disabled" : "") + ">" +
      "<span>" + (row.reviewed ? "Reviewed" : "Mark reviewed") + "</span>" + reviewedAt + "</label>";
    const detailAction = row.vulnerability_id
      ? "<button type='button' class='btn intelligence-action-btn' data-intelligence-id='" + escapeHtml(row.vulnerability_id) +
        "' data-intelligence-package='" + escapeHtml(row.package || "") + "' data-intelligence-version='" + escapeHtml(row.version || "") +
        "' data-intelligence-fixed='" + escapeHtml(row.fixed_version || "") + "'>View Details</button>"
      : "";
    const action = "<div class='alert-row-actions'>" + detailAction + reviewAction + "</div>";

    tr.innerHTML =
      "<td><span class='alert-queue-pill alert-queue-" + escapeHtml(row.action_queue) + "'>" + escapeHtml(ALERT_QUEUE_LABELS[row.action_queue] || row.action_queue) + "</span></td>" +
      "<td><span class='risk-score-pill risk-score-" + escapeHtml(row.risk_level || "low") + "'><strong>" + escapeHtml(row.risk_score == null ? "—" : row.risk_score) + "</strong><small>" + escapeHtml(row.risk_level || "unknown") + "</small></span></td>" +
      "<td><strong>" + escapeHtml(row.title) + "</strong><div class='alert-type-label'>" + escapeHtml(ALERT_TYPE_LABELS[row.type] || row.type) + "</div></td>" +
      "<td class='repository-cell' title='" + escapeHtml(row.repository) + "'>" + escapeHtml(row.repository) + "</td>" +
      "<td>" + packageText + vulnerabilityText + "</td>" +
      "<td class='alert-reason-cell'><strong>" + escapeHtml(row.recommended_action) + "</strong><div class='alert-type-label'>" + escapeHtml(row.message) + "</div></td>" +
      "<td>" + formatAlertDeadline(row) + "</td>" +
      "<td><span class='alert-status-pill alert-status-" + escapeHtml(row.status) + "'>" + escapeHtml(row.status) + "</span></td>" +
      "<td>" + action + "</td>";
    alertsTableBody.appendChild(tr);
  });
}

function fetchAlerts() {
  if (alertsStatusEl) alertsStatusEl.textContent = "Checking stored scans for security alerts...";
  return fetch("/api/alerts")
    .then(function(res) {
      return res.json().then(function(data) {
        if (!res.ok) throw new Error(data.error || "Could not load alerts");
        return data;
      });
    })
    .then(function(data) {
      const summary = data.summary || {};
      window._alertsData = data.alerts || [];
      if (alertsOpenCount) alertsOpenCount.textContent = summary.open || 0;
      if (alertsCriticalCount) alertsCriticalCount.textContent = summary.critical || 0;
      if (alertsHighCount) alertsHighCount.textContent = summary.high || 0;
      if (alertsReviewedCount) alertsReviewedCount.textContent = summary.reviewed || 0;
      if (alertsNotReviewedCount) alertsNotReviewedCount.textContent = summary.not_reviewed || 0;
      if (alertsResolvedCount) alertsResolvedCount.textContent = summary.resolved || 0;
      if (alertsRiskCriticalCount) alertsRiskCriticalCount.textContent = summary.risk_critical || 0;
      if (alertsRiskHighCount) alertsRiskHighCount.textContent = summary.risk_high || 0;
      if (alertsActNowCount) alertsActNowCount.textContent = summary.act_now || 0;
      if (alertsReviewSoonCount) alertsReviewSoonCount.textContent = summary.review_soon || 0;
      if (alertsMonitorCount) alertsMonitorCount.textContent = summary.monitor || 0;
      if (alertsCompletedCount) alertsCompletedCount.textContent = summary.completed || 0;
      if (alertsOverdueCount) alertsOverdueCount.textContent = (summary.overdue || 0) + " overdue";
      populateAlertRepositories(window._alertsData);
      renderAlerts();
      if (alertsStatusEl) {
        alertsStatusEl.textContent = window._alertsData.length
          ? window._alertsData.length + " alerts generated from real scan history. Use filters to focus on the most important findings."
          : "No actionable alerts are currently available. Run the same repository more than once to detect changes.";
      }
    })
    .catch(function(err) {
      console.error(err);
      if (alertsStatusEl) alertsStatusEl.textContent = "Error loading alerts: " + err.message;
      if (alertsTableBody) alertsTableBody.innerHTML = "<tr><td colspan='9' class='empty-cell'>Alerts could not be loaded.</td></tr>";
    });
}

function updateAlertReview(alertKey, reviewed) {
  return fetch("/api/alerts/" + encodeURIComponent(alertKey) + "/review", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ reviewed: reviewed })
  }).then(function(res) {
    return res.json().then(function(data) {
      if (!res.ok) throw new Error(data.error || "Could not save review status");
      return data;
    });
  }).then(fetchAlerts).catch(function(err) {
    if (alertsStatusEl) alertsStatusEl.textContent = "Error saving review status: " + err.message;
  });
}

function safeExternalUrl(value) {
  const url = String(value || "");
  return /^https?:\/\//i.test(url) ? url : "#";
}

function closeIntelligencePanel() {
  if (!intelligenceOverlay) return;
  intelligenceOverlay.classList.add("hidden");
  intelligenceOverlay.setAttribute("aria-hidden", "true");
  document.body.classList.remove("intelligence-open");
}

function renderIntelligence(data) {
  if (!intelligenceContent) return;
  const epss = data.epss_score == null ? "Not available" : (Number(data.epss_score) * 100).toFixed(1) + "%";
  const percentile = data.epss_percentile == null ? "—" : (Number(data.epss_percentile) * 100).toFixed(1) + "%";
  const repositories = (data.repositories || []).slice(0, 8).map(function(repository) {
    return "<li>" + escapeHtml(repository) + "</li>";
  }).join("") || "<li>No stored repository observation found.</li>";
  const references = (data.references || []).slice(0, 6).map(function(reference) {
    return "<li><a href='" + escapeHtml(safeExternalUrl(reference.url)) + "' target='_blank' rel='noopener noreferrer'>" +
      escapeHtml(reference.type || "Advisory") + "</a></li>";
  }).join("") || "<li>No additional advisory links were returned.</li>";
  const sources = data.sources || {};
  const sourceLinks = data.source_links || {};
  const risk = data.risk || {};
  const breakdown = risk.breakdown || {};
  const evidence = risk.evidence || {};
  const upgradeButton = data.fixed_version
    ? "<button type='button' class='btn btn-primary upgrade-analysis-btn' data-upgrade-analysis='true'>Analyze Recommended Version</button>"
    : "<span class='muted'>No fixed version is currently available for analysis.</span>";

  intelligenceContent.innerHTML =
    "<div class='intelligence-id-row'><div><span>Vulnerability</span><strong>" + escapeHtml(data.vulnerability_id) + "</strong></div>" +
      "<span class='severity-pill " + severityClass(data.severity) + "'>" + escapeHtml(data.severity || "Unknown") + "</span></div>" +
    "<h3 class='intelligence-summary'>" + escapeHtml(data.summary) + "</h3>" +
    "<div class='intelligence-signal-grid'>" +
      "<article class='risk-signal risk-score-" + escapeHtml(risk.level || "low") + "'><span>Risk Score</span><strong>" + escapeHtml(risk.score == null ? "—" : risk.score + " / 100") + "</strong><small>" + escapeHtml(risk.level || "Unknown") + " priority</small></article>" +
      "<article><span>CVSS Score</span><strong>" + escapeHtml(data.cvss_score == null ? "Not available" : data.cvss_score) + "</strong><small>" + escapeHtml(data.cvss_vector || "No vector returned") + "</small></article>" +
      "<article><span>EPSS Probability</span><strong>" + escapeHtml(epss) + "</strong><small>Percentile " + escapeHtml(percentile) + "</small></article>" +
      "<article class='" + (data.known_exploited ? "signal-danger" : "signal-safe") + "'><span>CISA KEV</span><strong>" + (data.known_exploited ? "Known Exploited" : "Not Listed") + "</strong><small>" + escapeHtml(data.kev_date_added || "Current catalog check") + "</small></article>" +
      "<article><span>Affected Repositories</span><strong>" + escapeHtml(data.affected_repositories || 0) + "</strong><small>Stored observations</small></article>" +
    "</div>" +
    "<div class='intelligence-section risk-breakdown-section'><h4>Risk score breakdown</h4><div class='risk-breakdown-grid'>" +
      "<span>Impact <strong>" + escapeHtml(breakdown.impact || 0) + "/40</strong></span>" +
      "<span>Exploitation <strong>" + escapeHtml(breakdown.exploitation || 0) + "/25</strong></span>" +
      "<span>Exposure <strong>" + escapeHtml(breakdown.repository_exposure || 0) + "/10</strong></span>" +
      "<span>Persistence <strong>" + escapeHtml(breakdown.persistence || 0) + "/10</strong></span>" +
      "<span>Remediation <strong>" + escapeHtml(breakdown.remediation || 0) + "/15</strong></span></div>" +
      "<p class='risk-evidence-note'>Evidence: CVSS " + (evidence.cvss_available ? "available" : "not available") +
      ", EPSS " + (evidence.epss_available ? "available" : "not available") +
      ", CISA KEV " + (evidence.cisa_kev_checked ? "checked" : "not checked") +
      ". Dependency depth is not stored and is excluded.</p></div>" +
    (data.known_exploited && data.kev_required_action ? "<div class='kev-action'><strong>CISA required action</strong><p>" + escapeHtml(data.kev_required_action) + "</p></div>" : "") +
    "<div class='intelligence-section'><h4>Advisory description</h4><p>" + escapeHtml(data.details) + "</p></div>" +
    "<div class='intelligence-detail-grid'>" +
      "<div><span>Package</span><strong>" + escapeHtml(data.package || "—") + "</strong></div>" +
      "<div><span>Fixed version</span><strong>" + escapeHtml(data.fixed_version || "Not available") + "</strong></div>" +
      "<div><span>First detected</span><strong>" + formatDateTime(data.first_detected) + "</strong></div>" +
      "<div><span>Latest detected</span><strong>" + formatDateTime(data.latest_detected) + "</strong></div>" +
      "<div><span>Published</span><strong>" + formatDateTime(data.published) + "</strong></div>" +
      "<div><span>Advisory updated</span><strong>" + formatDateTime(data.modified) + "</strong></div>" +
    "</div>" +
    "<div class='intelligence-two-column'>" +
      "<div class='intelligence-section'><h4>Affected repositories</h4><ul>" + repositories + "</ul></div>" +
      "<div class='intelligence-section'><h4>Advisory references</h4><ul>" + references + "</ul></div>" +
    "</div>" +
    "<div class='intelligence-section upgrade-analysis-section'><div class='upgrade-analysis-header'><div><h4>Upgrade Recommendation and Version Safety Check</h4><p>Check whether the recommended version resolves this vulnerability and whether OSV reports other known vulnerabilities in that version.</p></div>" + upgradeButton + "</div><div id='upgrade-analysis-result' class='upgrade-analysis-result'></div></div>" +
    "<div class='intelligence-sources'><strong>Data sources</strong>" +
      "<a href='" + escapeHtml(safeExternalUrl(sourceLinks.osv)) + "' target='_blank' rel='noopener noreferrer'>OSV: " + escapeHtml(sources.osv || "unavailable") + "</a>" +
      "<a href='" + escapeHtml(safeExternalUrl(sourceLinks.github)) + "' target='_blank' rel='noopener noreferrer'>GitHub Advisory: " + escapeHtml(sources.github || "not applicable") + "</a>" +
      "<a href='" + escapeHtml(safeExternalUrl(sourceLinks.epss)) + "' target='_blank' rel='noopener noreferrer'>EPSS: " + escapeHtml(sources.epss || "unavailable") + "</a>" +
      "<a href='" + escapeHtml(safeExternalUrl(sourceLinks.cisa_kev)) + "' target='_blank' rel='noopener noreferrer'>CISA KEV: " + escapeHtml(sources.cisa_kev || "unavailable") + "</a>" +
      "<span>Updated " + formatDateTime(data.fetched_at) + (data.cached ? " · cached" : "") + "</span></div>";
}

function openIntelligencePanel(vulnerabilityId, packageName, currentVersion, fixedVersion) {
  if (!intelligenceOverlay) return;
  intelligenceOverlay.classList.remove("hidden");
  intelligenceOverlay.setAttribute("aria-hidden", "false");
  document.body.classList.add("intelligence-open");
  if (intelligenceStatus) intelligenceStatus.textContent = "Loading OSV, EPSS and CISA KEV intelligence...";
  if (intelligenceContent) intelligenceContent.innerHTML = "<div class='intelligence-loading'>Collecting vulnerability intelligence...</div>";
  window._currentIntelligenceContext = { id: vulnerabilityId, package: packageName || "", current: currentVersion || "", fixed: fixedVersion || "" };

  fetch("/api/vulnerability-intelligence?id=" + encodeURIComponent(vulnerabilityId) + "&package=" + encodeURIComponent(packageName || "") + "&current=" + encodeURIComponent(currentVersion || ""))
    .then(function(res) {
      return res.json().then(function(data) {
        if (!res.ok) throw new Error(data.error || "Could not load vulnerability intelligence");
        return data;
      });
    })
    .then(function(data) {
      if (!window._currentIntelligenceContext.fixed) {
        window._currentIntelligenceContext.fixed = data.fixed_version || "";
      }
      renderIntelligence(data);
      if (intelligenceStatus) {
        intelligenceStatus.textContent = data.cached
          ? "Loaded from the local 24-hour intelligence cache."
          : "Intelligence retrieved and saved locally for 24 hours.";
      }
    })
    .catch(function(err) {
      if (intelligenceStatus) intelligenceStatus.textContent = "Error: " + err.message;
      if (intelligenceContent) intelligenceContent.innerHTML = "<div class='empty-state'>Intelligence details are temporarily unavailable.</div>";
    });
}

function runUpgradeAnalysis() {
  const context = window._currentIntelligenceContext || {};
  const resultEl = document.getElementById("upgrade-analysis-result");
  if (!resultEl) return;
  resultEl.innerHTML = "<div class='intelligence-loading compact-loading'>Checking the recommended version...</div>";
  const params = new URLSearchParams({ id: context.id || "", package: context.package || "", current: context.current || "", fixed: context.fixed || "" });
  fetch("/api/upgrade-analysis?" + params.toString())
    .then(function(res) { return res.json().then(function(data) { if (!res.ok) throw new Error(data.error || "Upgrade analysis failed"); return data; }); })
    .then(function(data) {
      const remaining = (data.remaining_vulnerabilities || []).map(function(item) {
        return "<li><strong>" + escapeHtml(item.id || "Unknown") + "</strong> — " + escapeHtml(item.summary || "No summary") + "</li>";
      }).join("") || (data.sources && data.sources.osv === "available"
        ? "<li>No known vulnerabilities were returned for the recommended version.</li>"
        : "<li>The OSV service was unavailable, so remaining vulnerabilities could not be verified.</li>");
      const resolvedText = data.current_vulnerability_resolved === true ? "Yes" : data.current_vulnerability_resolved === false ? "No" : "Could not verify";
      const resolvedClass = data.current_vulnerability_resolved === true ? "upgrade-good" : data.current_vulnerability_resolved === false ? "upgrade-danger" : "upgrade-warning";
      resultEl.innerHTML =
        "<div class='upgrade-result-grid'>" +
          "<article><span>Current version</span><strong>" + escapeHtml(data.current_version || "Unknown") + "</strong></article>" +
          "<article><span>Recommended version</span><strong>" + escapeHtml(data.recommended_version) + "</strong></article>" +
          "<article class='" + resolvedClass + "'><span>Current vulnerability resolved</span><strong>" + resolvedText + "</strong></article>" +
          "<article><span>Other known vulnerabilities</span><strong>" + escapeHtml(data.remaining_vulnerability_count == null ? "Could not verify" : data.remaining_vulnerability_count) + "</strong></article>" +
          "<article><span>Release date</span><strong>" + formatDateTime(data.release_date) + "</strong></article>" +
          "<article><span>Maintenance signal</span><strong>" + escapeHtml(data.maintenance_status) + "</strong></article>" +
          "<article><span>Latest registry version</span><strong>" + escapeHtml(data.latest_registry_version || "Unknown") + "</strong></article>" +
          "<article><span>Latest release date</span><strong>" + formatDateTime(data.latest_release_date) + "</strong></article>" +
          "<article class='upgrade-warning'><span>Compatibility</span><strong>" + escapeHtml(data.compatibility_status) + "</strong></article>" +
        "</div><div class='upgrade-known-problems'><h5>Known problems in the recommended version</h5><ul>" + remaining + "</ul></div>" +
        "<p class='upgrade-compatibility-note'>" + escapeHtml(data.compatibility_note) + "</p>";
    })
    .catch(function(err) { resultEl.innerHTML = "<div class='status-box error'>" + escapeHtml(err.message) + "</div>"; });
}

function setupAlertControls() {
  if (refreshAlertsBtn) refreshAlertsBtn.addEventListener("click", fetchAlerts);
  [alertsRepositoryFilter, alertsTypeFilter, alertsPriorityFilter, alertsStateFilter, alertsReviewFilter, alertsQueueFilter].forEach(function(control) {
    if (control) control.addEventListener("change", renderAlerts);
  });
  if (alertsSearch) alertsSearch.addEventListener("input", renderAlerts);
  document.querySelectorAll("[data-alert-queue]").forEach(function(button) {
    button.addEventListener("click", function() {
      if (alertsQueueFilter) alertsQueueFilter.value = this.getAttribute("data-alert-queue") || "all";
      renderAlerts();
      const table = document.getElementById("alerts-table");
      if (table) table.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  });
  if (alertsTableBody) {
    alertsTableBody.addEventListener("change", function(event) {
      const checkbox = event.target.closest(".alert-review-checkbox");
      if (!checkbox) return;
      checkbox.disabled = true;
      updateAlertReview(checkbox.getAttribute("data-alert-key"), checkbox.checked);
    });
    alertsTableBody.addEventListener("click", function(event) {
      const intelligenceButton = event.target.closest("[data-intelligence-id]");
      if (intelligenceButton) {
        openIntelligencePanel(
          intelligenceButton.getAttribute("data-intelligence-id"),
          intelligenceButton.getAttribute("data-intelligence-package"),
          intelligenceButton.getAttribute("data-intelligence-version"),
          intelligenceButton.getAttribute("data-intelligence-fixed")
        );
        return;
      }
    });
  }
  if (intelligenceClose) intelligenceClose.addEventListener("click", closeIntelligencePanel);
  if (intelligenceOverlay) {
    intelligenceOverlay.addEventListener("click", function(event) {
      if (event.target === intelligenceOverlay) closeIntelligencePanel();
    });
  }
  if (intelligenceContent) {
    intelligenceContent.addEventListener("click", function(event) {
      if (event.target.closest("[data-upgrade-analysis]")) runUpgradeAnalysis();
    });
  }
  document.addEventListener("keydown", function(event) {
    if (event.key === "Escape") closeIntelligencePanel();
  });
}

function setupForm() {
  if (!form) return;

  form.addEventListener("submit", function(event) {
    event.preventDefault();

    const target = targetInput.value.trim();
    if (!target) {
      setLoading(false, "Please enter a repository URL or local path.");
      return;
    }

    setLoading(true, "Preparing scan...");

    const payload = {
      target: target,
      useCache: useCacheInput.checked,
      shallowClone: shallowCloneInput.checked,
      skipVuln: false
    };

    const startTime = Date.now();

    fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    })
      .then(function(response) {
        if (!response.ok) {
          return response.json().then(function(err) {
            throw new Error(err.error || "Scan failed");
          });
        }
        return response.json();
      })
      .then(function(data) {
        if (!data.report) {
          throw new Error("No report data received");
        }

        renderSummary(data.report);
        renderTable(data.report.packages || []);
        renderDependencyTree(data.report.dependency_tree || []);

        const totalTime = Math.floor((Date.now() - startTime) / 1000);
        setLoading(false, "Scan completed successfully in " + totalTime + "s. Analytics refresh started in background.");

        switchPanel("results-panel");
        fetchLatestScans();
        fetchMonitorLog();
        fetchDatabaseSummary();
      })
      .catch(function(error) {
        console.error(error);
        setLoading(false, "Error: " + error.message);
      });
  });
}

function initApp() {
  initElements();
  setupSidebarNavigation();
  setupForm();
  setupAddTargetForm();
  setupImportForms();
  setupTargetFilters();
  setupScanAllActiveButton();
  setupAnalyticsControls();
  setupTimelineControls();
  setupBatchScanForm();
  setupSchedulerControls();
  setupAlertControls();

  renderImportHistory();
  fetchDataset();
  fetchMonitorLog();
  fetchLatestScans();
  fetchDatabaseSummary();
  fetchSchedulerStatus();
  loadRiskSettings();
  fetchAlerts();

  if (refreshSummaryBtn) {
    refreshSummaryBtn.addEventListener("click", fetchDatabaseSummary);
  }

  if (refreshMonitorBtn) {
    refreshMonitorBtn.addEventListener("click", fetchMonitorLog);
  }

  if (refreshDatasetBtn) {
    refreshDatasetBtn.addEventListener("click", fetchDataset);
  }

  setInterval(fetchDataset, 120000);
  setInterval(fetchMonitorLog, 120000);
  setInterval(fetchLatestScans, 120000);
  setInterval(fetchDatabaseSummary, 120000);
  setInterval(fetchSchedulerStatus, 10000);
  setInterval(fetchAlerts, 120000);
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initApp);
} else {
  initApp();
}

function renderDatabaseSummary(data) {
  const summary = data.summary || {};
  const totalVulnerabilities = parseInt(summary.total_vulnerabilities || 0, 10);

  if (dashTotalRepositories) dashTotalRepositories.textContent = summary.total_repositories || 0;
  if (dashTotalPackages) dashTotalPackages.textContent = summary.total_packages || 0;
  if (dashTotalScans) dashTotalScans.textContent = summary.total_scans || 0;
  if (dashTotalVulns) dashTotalVulns.textContent = totalVulnerabilities;

  if (severitySummaryEl) {
    severitySummaryEl.innerHTML = "";
    [
      ["Critical", "critical"], ["High", "high"], ["Medium", "medium"],
      ["Low", "low"], ["Negligible", "negligible"], ["Unknown", "unknown"]
    ].forEach(function(item) {
      const count = parseInt(summary[item[1]] || 0, 10);
      const percentage = totalVulnerabilities ? Math.round((count / totalVulnerabilities) * 100) : 0;
      const row = document.createElement("div");
      row.className = "severity-row severity-" + item[1];
      row.innerHTML =
        "<span class=\"severity-name\">" + item[0] + "</span>" +
        "<div class=\"severity-track\"><span style=\"width:" + percentage + "%\"></span></div>" +
        "<strong>" + count + "</strong>";
      severitySummaryEl.appendChild(row);
    });
  }

  if (topRepositoriesTableBody) {
    topRepositoriesTableBody.innerHTML = "";
    const rows = data.top_repositories || [];
    if (!rows.length) {
      topRepositoriesTableBody.innerHTML = "<tr><td colspan=\"4\" class=\"empty-cell\">No scans are available.</td></tr>";
    } else {
      rows.forEach(function(row) {
        const tr = document.createElement("tr");
        tr.innerHTML =
          "<td class=\"repository-cell\" title=\"" + escapeHtml(row.target_id) + "\">" + escapeHtml(row.target_id) + "</td>" +
          "<td><strong>" + escapeHtml(row.total_vulnerabilities || 0) + "</strong></td>" +
          "<td>" + escapeHtml(row.critical || 0) + "</td>" +
          "<td>" + escapeHtml(row.high || 0) + "</td>";
        topRepositoriesTableBody.appendChild(tr);
      });
    }
  }

  if (commonPackagesTableBody) {
    commonPackagesTableBody.innerHTML = "";
    const rows = data.common_packages || [];
    if (!rows.length) {
      commonPackagesTableBody.innerHTML = "<tr><td colspan=\"4\" class=\"empty-cell\">No affected packages are available.</td></tr>";
    } else {
      rows.forEach(function(row) {
        const severityClass = String(row.highest_severity || "unknown").toLowerCase();
        const tr = document.createElement("tr");
        tr.innerHTML =
          "<td><strong>" + escapeHtml(row.package_name) + "</strong></td>" +
          "<td>" + escapeHtml(row.affected_repositories || 0) + "</td>" +
          "<td>" + escapeHtml(row.vulnerability_occurrences || 0) + "</td>" +
          "<td><span class=\"severity-badge badge-" + severityClass + "\">" + escapeHtml(row.highest_severity) + "</span></td>";
        commonPackagesTableBody.appendChild(tr);
      });
    }
  }
}

function fetchDatabaseSummary() {
  if (summaryStatusEl) summaryStatusEl.textContent = "Loading database summary...";
  return fetch("/api/db/summary")
    .then(function(res) {
      if (!res.ok) throw new Error("Failed to load database summary");
      return res.json();
    })
    .then(function(data) {
      renderDatabaseSummary(data);
      if (summaryStatusEl) summaryStatusEl.textContent = data.scope || "";
      updateLastUpdatedText();
    })
    .catch(function(err) {
      console.error(err);
      if (summaryStatusEl) summaryStatusEl.textContent = "Error loading database summary.";
    });
}
