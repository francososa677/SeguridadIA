// Global State
let currentPruebas = [];
let activePolls = {}; // stores intervalIds for active test polling
let selectedPruebaResults = [];
let owaspChart = null;
let selectedCompareIds = [];
let compareResultsCache = {};
let compareChartAccuracyInstance = null;
let compareChartRatesInstance = null;

// DOM Elements
const navBtns = document.querySelectorAll('.nav-btn');
const tabContents = document.querySelectorAll('.tab-content');
const btnPing = document.getElementById('btn-ping');
const btnSaveConfig = document.getElementById('btn-save-config');
const ngrokUrlInput = document.getElementById('ngrok-url');
const pingStatus = document.getElementById('ping-status');
const pruebasGrid = document.getElementById('pruebas-grid');
const btnNuevaPrueba = document.getElementById('btn-nueva-prueba');
const modalPrueba = document.getElementById('modal-prueba');
const modalDiff = document.getElementById('modal-diff');
const formNuevaPrueba = document.getElementById('form-nueva-prueba');
const selectDataset = document.getElementById('prueba-dataset');
const navResultadosBtn = document.getElementById('nav-resultados-btn');

// Close buttons
const closeNuevaPrueba = document.getElementById('close-nueva-prueba');
const btnCancelNuevaPrueba = document.getElementById('btn-cancel-nueva-prueba');
const closeDiff = document.getElementById('close-diff');

// Tab 2 Elements
const activePruebaTitle = document.getElementById('active-prueba-title');
const activePruebaDesc = document.getElementById('active-prueba-desc');
const editPruebaDescContainer = document.getElementById('edit-prueba-desc-container');
const editPruebaNameInput = document.getElementById('edit-prueba-name-input');
const editPruebaDescInput = document.getElementById('edit-prueba-desc-input');
const btnSavePruebaDesc = document.getElementById('btn-save-prueba-desc');
const btnCancelPruebaDesc = document.getElementById('btn-cancel-prueba-desc');
const valPrecisionDet = document.getElementById('val-precision-det');
const valPrecisionClas = document.getElementById('val-precision-clas');
const barPrecisionDet = document.getElementById('bar-precision-det');
const barPrecisionClas = document.getElementById('bar-precision-clas');
const btnBackToPruebas = document.getElementById('btn-back-to-pruebas');
const tableSearch = document.getElementById('table-search');
const filterResult = document.getElementById('filter-result');
const resultadosTbody = document.getElementById('resultados-tbody');

// Diff Modal Elements
const diffTitle = document.getElementById('diff-title');
const diffCweReal = document.getElementById('diff-cwe-real');
const diffOwaspReal = document.getElementById('diff-owasp-real');
const diffOwaspPred = document.getElementById('diff-owasp-pred');
const diffCvss = document.getElementById('diff-cvss');
const diffVector = document.getElementById('diff-vector');
const diffExplicacion = document.getElementById('diff-explicacion');
const diffCodeOriginal = document.getElementById('diff-code-original');
const diffCodeParchado = document.getElementById('diff-code-parchado');

// Initialize Application
document.addEventListener('DOMContentLoaded', () => {
    initApp();
});

function initApp() {
    // 1. Fetch Config & Datasets
    fetchConfig();
    fetchDatasets();
    fetchPruebas();

    // 2. Tab Navigation
    navBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            const tabId = btn.getAttribute('data-tab');
            switchTab(tabId);
        });
    });

    btnBackToPruebas.addEventListener('click', () => {
        switchTab('tab-pruebas');
    });

    const btnDeleteActivePrueba = document.getElementById('btn-delete-active-prueba');
    btnDeleteActivePrueba.addEventListener('click', async () => {
        const activeId = navResultadosBtn.getAttribute('data-active-id');
        if (activeId) {
            await deletePrueba(activeId);
        }
    });

    // Edit test controls (nombre and descripcion)
    const startEditPrueba = () => {
        const activeId = navResultadosBtn.getAttribute('data-active-id');
        const p = currentPruebas.find(x => x.id === activeId);

        activePruebaTitle.style.display = 'none';
        activePruebaDesc.style.display = 'none';
        editPruebaDescContainer.style.display = 'flex';
        editPruebaNameInput.value = p ? p.nombre : activePruebaTitle.innerText;
        editPruebaDescInput.value = p ? (p.descripcion || '') : activePruebaDesc.innerText;
        editPruebaNameInput.focus();
    };

    activePruebaTitle.addEventListener('click', startEditPrueba);
    activePruebaDesc.addEventListener('click', startEditPrueba);

    btnCancelPruebaDesc.addEventListener('click', () => {
        editPruebaDescContainer.style.display = 'none';
        activePruebaTitle.style.display = 'block';
        activePruebaDesc.style.display = 'block';
    });

    btnSavePruebaDesc.addEventListener('click', async () => {
        const activeId = navResultadosBtn.getAttribute('data-active-id');
        if (!activeId) return;
        const newName = editPruebaNameInput.value.trim();
        const newDesc = editPruebaDescInput.value.trim();
        if (!newName) {
            alert('El nombre de la prueba no puede estar vacío.');
            return;
        }
        try {
            const res = await fetch(`/api/pruebas/${activeId}/descripcion`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ nombre: newName, descripcion: newDesc })
            });
            if (res.ok) {
                const data = await res.json();
                activePruebaTitle.innerText = data.nombre;
                activePruebaDesc.innerHTML = typeof marked !== 'undefined' ? marked.parse(data.descripcion || '') : (data.descripcion || '');

                // Update local model state
                const p = currentPruebas.find(x => x.id === activeId);
                if (p) {
                    p.nombre = data.nombre;
                    p.descripcion = data.descripcion;
                    p.resultados_file = data.resultados_file;
                }

                // Re-render list
                renderPruebasGrid();

                editPruebaDescContainer.style.display = 'none';
                activePruebaTitle.style.display = 'block';
                activePruebaDesc.style.display = 'block';
            } else {
                alert('No se pudo guardar la prueba.');
            }
        } catch (e) {
            alert(`Error: ${e.message}`);
        }
    });

    // Language filter dropdown listener
    const filterLenguaje = document.getElementById('filter-lenguaje');
    if (filterLenguaje) {
        filterLenguaje.addEventListener('change', () => {
            renderResultsTable();
            renderOwaspChart();
            renderConfusionMatrix();
        });
    }

    // 3. Modals Controls
    btnNuevaPrueba.addEventListener('click', () => {
        modalPrueba.classList.add('active');
        fetchDatasets(); // Refresh list on open
    });

    const closeModalPrueba = () => {
        modalPrueba.classList.remove('active');
        formNuevaPrueba.reset();
    };

    closeNuevaPrueba.addEventListener('click', closeModalPrueba);
    btnCancelNuevaPrueba.addEventListener('click', closeModalPrueba);
    closeDiff.addEventListener('click', () => modalDiff.classList.remove('active'));

    // Close on overlay click
    window.addEventListener('click', (e) => {
        if (e.target === modalPrueba) closeModalPrueba();
        if (e.target === modalDiff) modalDiff.classList.remove('active');
    });

    // 4. Form Submissions & Actions
    formNuevaPrueba.addEventListener('submit', handleCreatePrueba);
    btnSaveConfig.addEventListener('click', saveConfig);
    btnPing.addEventListener('click', testConnection);

    // 5. Table filter/search
    tableSearch.addEventListener('input', renderResultsTable);
    filterResult.addEventListener('change', renderResultsTable);
}

// Tab Switching
function switchTab(tabId) {
    navBtns.forEach(btn => {
        if (btn.getAttribute('data-tab') === tabId) {
            btn.classList.add('active');
        } else {
            btn.classList.remove('active');
        }
    });

    tabContents.forEach(content => {
        if (content.id === tabId) {
            content.classList.add('active');
        } else {
            content.classList.remove('active');
        }
    });
}

// Config Operations
async function fetchConfig() {
    try {
        const res = await fetch('/api/config');
        const data = await res.json();
        ngrokUrlInput.value = data.NGROK_URL || '';
    } catch (e) {
        console.error('Error fetching config:', e);
    }
}

async function saveConfig() {
    const url = ngrokUrlInput.value.trim();
    if (!url) {
        alert('Por favor ingrese una URL válida.');
        return;
    }

    btnSaveConfig.disabled = true;
    btnSaveConfig.innerText = 'Guardando...';
    try {
        const res = await fetch('/api/config', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ NGROK_URL: url })
        });
        if (res.ok) {
            alert('Configuración guardada exitosamente.');
            testConnection(); // Auto-ping after save
        } else {
            const err = await res.json();
            alert(`Error: ${err.detail}`);
        }
    } catch (e) {
        alert(`Error: ${e.message}`);
    } finally {
        btnSaveConfig.disabled = false;
        btnSaveConfig.innerText = 'Guardar URL';
    }
}

async function testConnection() {
    btnPing.disabled = true;
    btnPing.innerText = 'Probando...';
    pingStatus.className = 'ping-status-badge offline';
    pingStatus.innerHTML = '<span class="indicator"></span> Probando conexión...';

    try {
        const res = await fetch('/api/ping');
        const data = await res.json();

        if (data.connected) {
            pingStatus.className = 'ping-status-badge online';
            pingStatus.innerHTML = `<span class="indicator"></span> Online (${data.elapsed}s) - ${data.info.model || 'API Ready'}`;
        } else {
            pingStatus.className = 'ping-status-badge offline';
            pingStatus.innerHTML = `<span class="indicator"></span> Desconectado: ${data.detail || 'Fallo'}`;
        }
    } catch (e) {
        pingStatus.className = 'ping-status-badge offline';
        pingStatus.innerHTML = `<span class="indicator"></span> Error de red`;
    } finally {
        btnPing.disabled = false;
        btnPing.innerText = 'Hacer Ping';
    }
}

// Datasets Operations
async function fetchDatasets() {
    try {
        const res = await fetch('/api/datasets');
        const files = await res.json();

        selectDataset.innerHTML = '<option value="">-- Seleccionar Dataset --</option>';
        files.forEach(file => {
            selectDataset.innerHTML += `<option value="${file}">${file}</option>`;
        });
    } catch (e) {
        selectDataset.innerHTML = '<option value="">Error cargando datasets</option>';
    }
}

// Pruebas Operations
async function fetchPruebas() {
    try {
        const res = await fetch('/api/pruebas');
        currentPruebas = await res.json();
        renderPruebasGrid();
        renderCompareSelection();
    } catch (e) {
        pruebasGrid.innerHTML = `<div class="no-data">Error al cargar las pruebas: ${e.message}</div>`;
    }
}

async function handleCreatePrueba(e) {
    e.preventDefault();
    const nombre = document.getElementById('prueba-nombre').value.trim();
    const descripcion = document.getElementById('prueba-desc').value.trim();
    const dataset = selectDataset.value;

    if (!nombre || !descripcion || !dataset) {
        alert('Por favor complete todos los campos.');
        return;
    }

    const submitBtn = formNuevaPrueba.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.innerText = 'Iniciando...';

    try {
        const res = await fetch('/api/pruebas', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ nombre, descripcion, dataset })
        });

        if (res.ok) {
            modalPrueba.classList.remove('active');
            formNuevaPrueba.reset();
            await fetchPruebas(); // Reload list
        } else {
            const err = await res.json();
            alert(`Error: ${err.detail}`);
        }
    } catch (e) {
        alert(`Error de red: ${e.message}`);
    } finally {
        submitBtn.disabled = false;
        submitBtn.innerText = 'Iniciar Experimento';
    }
}

function renderPruebasGrid() {
    if (currentPruebas.length === 0) {
        pruebasGrid.innerHTML = '<div class="no-data">No se han registrado pruebas. Crea una nueva prueba arriba.</div>';
        return;
    }

    pruebasGrid.innerHTML = '';

    // Render in reverse chronological order (newest first)
    [...currentPruebas].reverse().forEach(p => {
        const isRunning = p.status === 'running';

        const card = document.createElement('div');
        card.className = `prueba-card card`;
        card.id = `card-${p.id}`;

        const truncatedDesc = p.descripcion && p.descripcion.length > 50
            ? p.descripcion.substring(0, 100) + '...'
            : (p.descripcion || '');

        let headerHtml = `
            <div class="prueba-card-header">
                <h3>${escapeHTML(p.nombre)}</h3>
                <span class="status-badge ${p.status}">${translateStatus(p.status)}</span>
            </div>
            <p class="prueba-card-desc" title="${escapeHTML(p.descripcion || '')}">${escapeHTML(truncatedDesc)}</p>
        `;

        let progressHtml = '';
        if (isRunning) {
            const initialTotal = p.total_casos !== null && p.total_casos !== undefined ? p.total_casos : 0;
            const initialAnalizados = p.casos_analizados !== null && p.casos_analizados !== undefined ? p.casos_analizados : 0;

            progressHtml = `
                <div class="run-progress-container" id="prog-container-${p.id}">
                    <div class="run-progress-header">
                        <span>Progreso: <strong id="prog-cases-${p.id}">${initialAnalizados}/${initialTotal}</strong> casos</span>
                        <span id="prog-text-${p.id}">0%</span>
                    </div>
                    <div class="progressbar">
                        <div class="progressbar-fill" id="prog-bar-${p.id}" style="width: 0%"></div>
                    </div>
                </div>
                <div class="logs-console" id="console-${p.id}">
                    <div class="log-line">Iniciando tarea en segundo plano...</div>
                </div>
                <div class="prueba-card-actions">
                    <button class="btn btn-danger btn-sm" onclick="cancelPrueba('${p.id}', event)">Detener</button>
                </div>
            `;
            // Trigger background status polling
            pollPruebaStatus(p.id);
        } else {
            // Completed / Canceled / Failed Card Content
            const hasResults = p.status === 'completed' || p.status === 'canceled';
            const det = p.precision_deteccion !== null ? `${p.precision_deteccion}%` : '--';
            const clas = p.precision_clasificacion !== null ? `${p.precision_clasificacion}%` : '--';

            const showCases = p.total_casos !== undefined && p.total_casos !== null;
            const casesSpan = showCases
                ? `<span>Casos: <strong>${p.casos_analizados} / ${p.total_casos}</strong></span>`
                : '';

            const showTime = p.tiempo_promedio !== undefined && p.tiempo_promedio !== null;
            const timeSpan = showTime
                ? `<span>Tiempo promedio: <strong>${p.tiempo_promedio} s</strong></span>`
                : '';

            progressHtml = `
                <div class="prueba-card-meta">
                    <span>Dataset: <strong>${escapeHTML(p.dataset)}</strong></span>
                    <span>Fecha: <strong>${p.fecha_creacion}</strong></span>
                    ${casesSpan}
                    ${timeSpan}
                </div>
                ${hasResults ? `
                <div class="card-results-metrics">
                    <div class="card-metric">
                        <span class="num">${det}</span>
                        <span class="lbl">Precisión Det.</span>
                    </div>
                    <div class="card-metric highlight">
                        <span class="num">${clas}</span>
                        <span class="lbl">Precisión Clas.</span>
                    </div>
                </div>
                ` : ''}
                <div class="prueba-card-actions">
                    ${hasResults ? `<button class="btn btn-primary" onclick="viewPruebaDetails('${p.id}', event)">Ver Reporte</button>` : ''}
                    ${((p.status === 'canceled' || p.status === 'failed') && p.total_casos && p.casos_analizados < p.total_casos) ? `<button class="btn btn-success" style="background-color: var(--success-color, #10b981); border-color: var(--success-color, #10b981);" onclick="resumePrueba('${p.id}', event)">▶️ Reanudar</button>` : ''}
                    <button class="btn btn-secondary btn-icon" onclick="deletePrueba('${p.id}', event)" title="Eliminar prueba">🗑️</button>
                </div>
            `;

            // Clean up any old polling just in case
            if (activePolls[p.id]) {
                clearInterval(activePolls[p.id]);
                delete activePolls[p.id];
            }
        }

        card.innerHTML = headerHtml + progressHtml;
        pruebasGrid.appendChild(card);
    });
}

// Polling status for running test
function pollPruebaStatus(pruebaId) {
    if (activePolls[pruebaId]) return; // already polling

    const intervalId = setInterval(async () => {
        try {
            const res = await fetch(`/api/pruebas/${pruebaId}/status`);
            if (!res.ok) {
                clearInterval(intervalId);
                delete activePolls[pruebaId];
                return;
            }

            const data = await res.json();

            // Update Progress UI elements
            const progText = document.getElementById(`prog-text-${pruebaId}`);
            const progBar = document.getElementById(`prog-bar-${pruebaId}`);
            const progCases = document.getElementById(`prog-cases-${pruebaId}`);
            const logsConsole = document.getElementById(`console-${pruebaId}`);

            if (progText) progText.innerText = `${data.progress}%`;
            if (progBar) progBar.style.width = `${data.progress}%`;
            if (progCases && data.casos_analizados !== undefined && data.total_casos !== undefined) {
                progCases.innerText = `${data.casos_analizados}/${data.total_casos}`;
            }

            if (logsConsole && data.logs) {
                // Populate log console lines
                logsConsole.innerHTML = '';
                data.logs.forEach(log => {
                    const logEl = document.createElement('div');
                    logEl.className = 'log-line';
                    if (log.includes('❌') || log.includes('Falló')) logEl.classList.add('error');
                    else if (log.includes('⚠️')) logEl.classList.add('warn');
                    else if (log.includes('🔍') || log.includes('📊') || log.includes('💾')) logEl.classList.add('info');
                    logEl.innerText = log;
                    logsConsole.appendChild(logEl);
                });
                // scroll to bottom
                logsConsole.scrollTop = logsConsole.scrollHeight;
            }

            // If completed or failed, stop polling and reload
            if (data.status !== 'running') {
                clearInterval(intervalId);
                delete activePolls[pruebaId];
                fetchPruebas(); // Reload all cards
            }
        } catch (e) {
            console.error('Error polling status:', e);
        }
    }, 30000);

    activePolls[pruebaId] = intervalId;
}

async function cancelPrueba(pruebaId, event) {
    if (event) event.stopPropagation();
    if (!confirm('¿Estás seguro de que deseas detener la prueba? Los resultados procesados hasta ahora se guardarán.')) return;

    try {
        const res = await fetch(`/api/pruebas/${pruebaId}/cancel`, { method: 'POST' });
        if (res.ok) {
            alert('Cancelación solicitada. Se guardarán los datos consolidados en breve.');
        } else {
            alert('No se pudo cancelar la prueba.');
        }
    } catch (e) {
        alert(`Error: ${e.message}`);
    }
}

async function deletePrueba(pruebaId, event) {
    if (event) event.stopPropagation();
    if (!confirm('¿Estás seguro de que deseas eliminar esta prueba permanentemente junto con su archivo de resultados?')) return;

    try {
        const res = await fetch(`/api/pruebas/${pruebaId}`, { method: 'DELETE' });
        if (res.ok) {
            // Remove poll if active
            if (activePolls[pruebaId]) {
                clearInterval(activePolls[pruebaId]);
                delete activePolls[pruebaId];
            }
            fetchPruebas();

            // If active displayed test is deleted, disable report tab
            if (navResultadosBtn.getAttribute('data-active-id') === pruebaId) {
                navResultadosBtn.disabled = true;
                switchTab('tab-pruebas');
            }
        } else {
            alert('No se pudo eliminar la prueba.');
        }
    } catch (e) {
        alert(`Error: ${e.message}`);
    }
}

// TAB 2: Detailed report viewer
async function viewPruebaDetails(pruebaId, event) {
    if (event) event.stopPropagation();

    const p = currentPruebas.find(x => x.id === pruebaId);
    if (!p) return;

    activePruebaTitle.innerText = p.nombre;
    activePruebaDesc.innerHTML = typeof marked !== 'undefined' ? marked.parse(p.descripcion || '') : (p.descripcion || '');

    // Set system prompt used
    const activePruebaPromptVal = document.getElementById('active-prueba-prompt-val');
    if (activePruebaPromptVal) {
        activePruebaPromptVal.innerText = p.system_prompt || '';
    }

    // Set metadata values
    document.getElementById('active-prueba-dataset-val').innerText = p.dataset;
    document.getElementById('active-prueba-date-val').innerText = p.fecha_creacion;

    const totalC = p.total_casos !== undefined && p.total_casos !== null ? p.total_casos : '--';
    const analizadosC = p.casos_analizados !== undefined && p.casos_analizados !== null ? p.casos_analizados : '--';
    document.getElementById('active-prueba-cases-val').innerText = `${analizadosC} / ${totalC}`;

    const avgT = p.tiempo_promedio !== undefined && p.tiempo_promedio !== null ? `${p.tiempo_promedio} s` : '--';
    document.getElementById('active-prueba-avgtime-val').innerText = avgT;

    // Reset description edit container state
    editPruebaDescContainer.style.display = 'none';
    activePruebaDesc.style.display = 'block';

    // Set KPI numbers
    valPrecisionDet.innerText = p.precision_deteccion !== null ? `${p.precision_deteccion}%` : '--%';
    valPrecisionClas.innerText = p.precision_clasificacion !== null ? `${p.precision_clasificacion}%` : '--%';
    barPrecisionDet.style.width = p.precision_deteccion !== null ? `${p.precision_deteccion}%` : '0%';
    barPrecisionClas.style.width = p.precision_clasificacion !== null ? `${p.precision_clasificacion}%` : '0%';

    // Load results CSV
    try {
        resultadosTbody.innerHTML = '<tr><td colspan="10" style="text-align:center;">Cargando resultados...</td></tr>';

        // Reset language filter to todos
        const filterLenguaje = document.getElementById('filter-lenguaje');
        if (filterLenguaje) {
            filterLenguaje.value = 'todos';
        }

        // Enable nav tab and set active ID metadata
        navResultadosBtn.disabled = false;
        navResultadosBtn.setAttribute('data-active-id', pruebaId);
        switchTab('tab-resultados');

        const res = await fetch(`/api/pruebas/${pruebaId}/resultados`);
        selectedPruebaResults = await res.json();

        if (p.total_casos === null || p.total_casos === undefined) {
            document.getElementById('active-prueba-cases-val').innerText = `${selectedPruebaResults.length} / ${selectedPruebaResults.length}`;
        }

        if (p.tiempo_promedio === null || p.tiempo_promedio === undefined) {
            const times = selectedPruebaResults.map(r => r.tiempo_segundos).filter(t => t !== undefined && t !== null);
            if (times.length > 0) {
                const avg = (times.reduce((sum, val) => sum + val, 0) / times.length).toFixed(2);
                document.getElementById('active-prueba-avgtime-val').innerText = `${avg} s`;
            }
        }

        renderResultsTable();
        renderOwaspChart();
        renderConfusionMatrix();
        renderLanguageBreakdown();
    } catch (e) {
        resultadosTbody.innerHTML = `<tr><td colspan="10" style="text-align:center; color:var(--danger)">Error: ${e.message}</td></tr>`;
    }
}

// Render filtered results table
function renderResultsTable() {
    const search = tableSearch.value.toLowerCase().trim();
    const filter = filterResult.value;

    const selectedLang = document.getElementById('filter-lenguaje').value;
    const filtered = selectedPruebaResults.filter(row => {
        // Apply language filter
        if (selectedLang !== 'todos' && String(row.lenguaje).toLowerCase() !== selectedLang.toLowerCase()) {
            return false;
        }

        // Apply search query
        const matchesSearch =
            String(row.id).toLowerCase().includes(search) ||
            String(row.cwe_ground_truth).toLowerCase().includes(search) ||
            String(row.owasp_ground_truth).toLowerCase().includes(search) ||
            String(row.owasp_categoria_predicho).toLowerCase().includes(search) ||
            String(row.explicacion).toLowerCase().includes(search);

        // Apply status filter
        let matchesFilter = true;
        const detCorrect = String(row.acierto_deteccion).toLowerCase() === 'true';
        const clasCorrect = String(row.acierto_clasificacion).toLowerCase() === 'true';

        if (filter === 'acierto_det') matchesFilter = detCorrect;
        else if (filter === 'fallo_det') matchesFilter = !detCorrect;
        else if (filter === 'acierto_clas') matchesFilter = clasCorrect;
        else if (filter === 'fallo_clas') matchesFilter = !clasCorrect;

        return matchesSearch && matchesFilter;
    });

    if (filtered.length === 0) {
        resultadosTbody.innerHTML = '<tr><td colspan="10" style="text-align:center;">No se encontraron registros que coincidan con la búsqueda.</td></tr>';
        return;
    }

    resultadosTbody.innerHTML = '';
    filtered.forEach(row => {
        const tr = document.createElement('tr');
        const detCorrect = String(row.acierto_deteccion).toLowerCase() === 'true';
        const clasCorrect = String(row.acierto_clasificacion).toLowerCase() === 'true';
        const score = parseFloat(row.cvss_score) || 0;

        tr.innerHTML = `
            <td><strong>${escapeHTML(row.id)}</strong></td>
            <td><span class="badge-lang">${escapeHTML(row.lenguaje)}</span></td>
            <td><span class="mono">${escapeHTML(row.cwe_ground_truth)}</span></td>
            <td><span class="mono" style="font-size:0.75rem">${escapeHTML(row.owasp_ground_truth)}</span></td>
            <td><span class="mono" style="font-size:0.75rem">${escapeHTML(row.owasp_categoria_predicho)}</span></td>
            <td><span class="badge-boolean ${detCorrect ? 'success' : 'danger'}">${detCorrect ? '✓' : '✗'}</span></td>
            <td><span class="badge-boolean ${clasCorrect ? 'success' : 'danger'}">${clasCorrect ? '✓' : '✗'}</span></td>
            <td><span class="cvss-badge ${getCvssClass(score)}">${score.toFixed(1)}</span></td>
            <td>${row.tiempo_segundos}s</td>
            <td><button class="btn btn-secondary btn-sm" onclick="openDiffModal('${escapeHTML(row.id)}')">Ver</button></td>
        `;
        resultadosTbody.appendChild(tr);
    });
}

// Chart rendering
function renderOwaspChart() {
    const ctx = document.getElementById('owasp-chart').getContext('2d');

    // Destroy previous instance
    if (owaspChart) {
        owaspChart.destroy();
    }

    // Count occurrences of predicted categories
    const selectedLang = document.getElementById('filter-lenguaje').value;
    const filteredResults = selectedLang === 'todos'
        ? selectedPruebaResults
        : selectedPruebaResults.filter(item => String(item.lenguaje).toLowerCase() === selectedLang.toLowerCase());

    const counts = {};
    filteredResults.forEach(row => {
        const cat = row.owasp_categoria_predicho || 'ERROR';
        counts[cat] = (counts[cat] || 0) + 1;
    });

    const labels = Object.keys(counts);
    const data = Object.values(counts);

    // Palette with Sleek Dark Mode colors
    const colors = [
        '#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6',
        '#EC4899', '#06B6D4', '#14B8A6', '#F43F5E', '#1E1B4B',
        '#6B7280', '#0284C7'
    ];

    owaspChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: data,
                backgroundColor: colors.slice(0, labels.length),
                borderColor: '#161E31',
                borderWidth: 2
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#9CA3AF',
                        font: { family: 'Outfit', size: 9 },
                        boxWidth: 10
                    }
                }
            }
        }
    });
}

// Detailed comparison popup (Diff modal)
function openDiffModal(rowId) {
    const row = selectedPruebaResults.find(x => x.id === rowId);
    if (!row) return;

    diffTitle.innerText = `Detalle del Caso: ${row.id}`;
    diffCweReal.innerText = row.cwe_ground_truth;
    diffOwaspReal.innerText = row.owasp_ground_truth;
    diffOwaspPred.innerText = row.owasp_categoria_predicho;

    const score = parseFloat(row.cvss_score) || 0;
    diffCvss.innerText = score.toFixed(1);
    diffCvss.className = `cvss-badge ${getCvssClass(score)}`;
    diffVector.innerText = row.cvss_vector || 'Ninguno';

    diffExplicacion.innerText = row.explicacion || 'No hay explicación disponible.';

    // Fill code views
    diffCodeOriginal.innerText = row.codigo_original || '// Código no disponible';
    diffCodeParchado.innerText = row.codigo_parchado || '// No se generó código de reparación o es seguro';

    modalDiff.classList.add('active');
}

// Helpers
function escapeHTML(str) {
    if (!str) return '';
    return str.replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

function translateStatus(s) {
    const map = {
        'running': 'Corriendo',
        'completed': 'Completada',
        'failed': 'Fallida',
        'canceled': 'Detenida'
    };
    return map[s] || s;
}

function getCvssClass(score) {
    if (score >= 9.0) return 'critical';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'medium';
    if (score > 0.0) return 'low';
    return 'none';
}

function renderConfusionMatrix() {
    let tp = 0, tn = 0, fp = 0, fn = 0;

    const selectedLang = document.getElementById('filter-lenguaje').value;
    const filteredResults = selectedLang === 'todos'
        ? selectedPruebaResults
        : selectedPruebaResults.filter(item => String(item.lenguaje).toLowerCase() === selectedLang.toLowerCase());

    filteredResults.forEach(item => {
        const isRealVulnerable = item.owasp_ground_truth && item.owasp_ground_truth.toUpperCase() !== 'SEGURO';
        const isPredVulnerable = item.estado_predicho && item.estado_predicho.toUpperCase() === 'VULNERABLE';

        if (isRealVulnerable && isPredVulnerable) {
            tp++;
        } else if (isRealVulnerable && !isPredVulnerable) {
            fn++;
        } else if (!isRealVulnerable && isPredVulnerable) {
            fp++;
        } else if (!isRealVulnerable && !isPredVulnerable) {
            tn++;
        }
    });

    // Update DOM counts
    document.getElementById('val-tp').innerText = tp;
    document.getElementById('val-tn').innerText = tn;
    document.getElementById('val-fp').innerText = fp;
    document.getElementById('val-fn').innerText = fn;

    // Calculate metrics
    const precisionVal = (tp + fp) > 0 ? (tp / (tp + fp)) * 100 : 0;
    const recallVal = (tp + fn) > 0 ? (tp / (tp + fn)) * 100 : 0;
    const specificityVal = (tn + fp) > 0 ? (tn / (tn + fp)) * 100 : 0;
    const f1Val = (precisionVal + recallVal) > 0 ? 2 * (precisionVal * recallVal) / (precisionVal + recallVal) : 0;

    // Update DOM metrics
    document.getElementById('metric-precision').innerText = `${precisionVal.toFixed(1)}%`;
    document.getElementById('metric-recall').innerText = `${recallVal.toFixed(1)}%`;
    document.getElementById('metric-specificity').innerText = `${specificityVal.toFixed(1)}%`;
    document.getElementById('metric-f1').innerText = `${f1Val.toFixed(1)}%`;

    // Also update dynamic overall KPIs for the selected language
    if (filteredResults.length > 0) {
        const detCorrectCount = filteredResults.filter(item => String(item.acierto_deteccion).toLowerCase() === 'true').length;
        const clasCorrectCount = filteredResults.filter(item => String(item.acierto_clasificacion).toLowerCase() === 'true').length;

        const detPrecision = (detCorrectCount / filteredResults.length) * 100;
        const clasPrecision = (clasCorrectCount / filteredResults.length) * 100;

        valPrecisionDet.innerText = `${detPrecision.toFixed(1)}%`;
        valPrecisionClas.innerText = `${clasPrecision.toFixed(1)}%`;
        barPrecisionDet.style.width = `${detPrecision}%`;
        barPrecisionClas.style.width = `${clasPrecision}%`;
    } else {
        valPrecisionDet.innerText = '--%';
        valPrecisionClas.innerText = '--%';
        barPrecisionDet.style.width = '0%';
        barPrecisionClas.style.width = '0%';
    }
}

function renderLanguageBreakdown() {
    const tbody = document.getElementById('desglose-lenguajes-tbody');
    if (!tbody) return;

    const langGroups = {};
    selectedPruebaResults.forEach(item => {
        const lang = (item.lenguaje || 'unknown').toLowerCase();
        if (!langGroups[lang]) {
            langGroups[lang] = [];
        }
        langGroups[lang].push(item);
    });

    const sortedLangs = Object.keys(langGroups).sort();

    if (sortedLangs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 12px; opacity:0.7;">No hay desglose disponible.</td></tr>';
        return;
    }

    tbody.innerHTML = '';
    sortedLangs.forEach(lang => {
        const items = langGroups[lang];
        const total = items.length;

        const detCorrect = items.filter(x => String(x.acierto_deteccion).toLowerCase() === 'true').length;
        const clasCorrect = items.filter(x => String(x.acierto_clasificacion).toLowerCase() === 'true').length;

        const detPct = total > 0 ? (detCorrect / total) * 100 : 0;
        const clasPct = total > 0 ? (clasCorrect / total) * 100 : 0;

        const times = items.map(x => parseFloat(x.tiempo_segundos)).filter(t => !isNaN(t));
        const avgTime = times.length > 0 ? (times.reduce((a, b) => a + b, 0) / times.length).toFixed(2) + ' s' : '--';

        const tr = document.createElement('tr');
        tr.style.borderBottom = '1px solid rgba(255,255,255,0.05)';

        tr.innerHTML = `
            <td style="padding: 12px; font-weight: 500;"><span class="badge-lang">${escapeHTML(lang.toUpperCase())}</span></td>
            <td style="padding: 12px; text-align: center;"><strong>${total}</strong></td>
            <td style="padding: 12px; text-align: center;">
                <div style="display: flex; align-items: center; justify-content: center; gap: 8px;">
                    <span style="font-weight: 600; color: ${detPct >= 80 ? '#2ecc71' : detPct >= 50 ? '#f1c40f' : '#e74c3c'}">${detPct.toFixed(1)}%</span>
                    <span style="font-size: 0.75rem; opacity: 0.7;">(${detCorrect}/${total})</span>
                </div>
            </td>
            <td style="padding: 12px; text-align: center;">
                <div style="display: flex; align-items: center; justify-content: center; gap: 8px;">
                    <span style="font-weight: 600; color: ${clasPct >= 80 ? '#2ecc71' : clasPct >= 50 ? '#f1c40f' : '#e74c3c'}">${clasPct.toFixed(1)}%</span>
                    <span style="font-size: 0.75rem; opacity: 0.7;">(${clasCorrect}/${total})</span>
                </div>
            </td>
            <td style="padding: 12px; text-align: center; opacity: 0.85;">${avgTime}</td>
        `;
        tbody.appendChild(tr);
    });
}

async function resumePrueba(pruebaId, event) {
    if (event) event.stopPropagation();
    try {
        const response = await fetch(`/api/pruebas/${pruebaId}/resume`, {
            method: 'POST'
        });
        if (response.ok) {
            fetchPruebas(); // Reload all cards to show progress bar
        } else {
            const err = await response.json();
            alert('Error al reanudar la prueba: ' + (err.detail || 'Error desconocido'));
        }
    } catch (e) {
        console.error('Error resuming trial:', e);
        alert('Error al reanudar la prueba.');
    }
}

// === COMPARISON TAB LOGIC ===

function renderCompareSelection() {
    const container = document.getElementById('compare-selection-container');
    if (!container) return;
    
    const completedPruebas = currentPruebas.filter(p => p.status === 'completed' || p.status === 'canceled');
    if (completedPruebas.length === 0) {
        container.innerHTML = '<div class="no-data" style="padding: 10px; width: 100%;">No hay pruebas disponibles para comparar. Completa al menos dos experimentos.</div>';
        return;
    }
    
    container.innerHTML = '';
    completedPruebas.forEach(p => {
        const div = document.createElement('div');
        div.style.display = 'flex';
        div.style.alignItems = 'center';
        div.style.gap = '0.5rem';
        div.style.padding = '8px 14px';
        div.style.background = 'rgba(255,255,255,0.03)';
        div.style.border = '1px solid rgba(255,255,255,0.06)';
        div.style.borderRadius = '6px';
        div.style.cursor = 'pointer';
        div.style.transition = 'background 0.2s';
        
        div.addEventListener('mouseenter', () => div.style.background = 'rgba(255,255,255,0.06)');
        div.addEventListener('mouseleave', () => div.style.background = 'rgba(255,255,255,0.03)');
        
        const isChecked = selectedCompareIds.includes(p.id) ? 'checked' : '';
        div.innerHTML = `
            <input type="checkbox" id="chk-${p.id}" value="${p.id}" ${isChecked} style="cursor: pointer; width: 16px; height: 16px;">
            <label for="chk-${p.id}" style="cursor: pointer; font-size: 0.9rem; font-weight: 500; user-select: none;">
                ${escapeHTML(p.nombre)} <span style="font-size: 0.75rem; opacity: 0.5; margin-left: 0.25rem;">(${p.fecha_creacion})</span>
            </label>
        `;
        
        div.addEventListener('click', (e) => {
            if (e.target.tagName !== 'INPUT') {
                const chk = div.querySelector('input');
                chk.checked = !chk.checked;
                chk.dispatchEvent(new Event('change'));
            }
        });
        
        const chk = div.querySelector('input');
        chk.addEventListener('change', async (e) => {
            if (e.target.checked) {
                if (!selectedCompareIds.includes(p.id)) {
                    selectedCompareIds.push(p.id);
                }
            } else {
                selectedCompareIds = selectedCompareIds.filter(id => id !== p.id);
            }
            await updateComparisonView();
        });
        
        container.appendChild(div);
    });
}

async function updateComparisonView() {
    const resultsContainer = document.getElementById('compare-results-container');
    const noSelectionContainer = document.getElementById('compare-no-selection');
    
    if (selectedCompareIds.length < 2) {
        resultsContainer.style.display = 'none';
        noSelectionContainer.style.display = 'block';
        return;
    }
    
    noSelectionContainer.style.display = 'none';
    resultsContainer.style.display = 'flex';
    
    const trialsData = [];
    for (const id of selectedCompareIds) {
        const p = currentPruebas.find(x => x.id === id);
        if (!p) continue;
        
        if (!compareResultsCache[id]) {
            try {
                const res = await fetch(`/api/pruebas/${id}/resultados`);
                if (res.ok) {
                    compareResultsCache[id] = await res.json();
                } else {
                    compareResultsCache[id] = [];
                }
            } catch (e) {
                console.error(`Error loading results for ${id}:`, e);
                compareResultsCache[id] = [];
            }
        }
        
        const results = compareResultsCache[id];
        let tp = 0, tn = 0, fp = 0, fn = 0;
        
        results.forEach(item => {
            const isRealVulnerable = item.owasp_ground_truth && String(item.owasp_ground_truth).toLowerCase() !== 'seguro';
            const isPredVulnerable = item.estado_predicho && String(item.estado_predicho).toUpperCase() === 'VULNERABLE';
            
            if (isRealVulnerable && isPredVulnerable) {
                tp++;
            } else if (isRealVulnerable && !isPredVulnerable) {
                fn++;
            } else if (!isRealVulnerable && isPredVulnerable) {
                fp++;
            } else {
                tn++;
            }
        });
        
        const total = results.length;
        const detCorrect = results.filter(item => String(item.acierto_deteccion).toLowerCase() === 'true').length;
        const clasCorrect = results.filter(item => String(item.acierto_classification || item.acierto_clasificacion).toLowerCase() === 'true').length;
        
        const accuracyDet = total > 0 ? (detCorrect / total) * 100 : 0;
        const accuracyClas = total > 0 ? (clasCorrect / total) * 100 : 0;
        const recall = (tp + fn) > 0 ? (tp / (tp + fn)) * 100 : 0;
        const fpr = (fp + tn) > 0 ? (fp / (fp + tn)) * 100 : 0;
        const fnr = (fn + tp) > 0 ? (fn / (fn + tp)) * 100 : 0;
        
        trialsData.push({
            id: p.id,
            nombre: p.nombre,
            fecha: p.fecha_creacion,
            dataset: p.dataset,
            casos: total,
            accuracyDet: accuracyDet.toFixed(1),
            accuracyClas: accuracyClas.toFixed(1),
            recall: recall.toFixed(1),
            fpr: fpr.toFixed(1),
            fnr: fnr.toFixed(1),
            tp, tn, fp, fn,
            tiempo_promedio: p.tiempo_promedio
        });
    }
    
    renderCompareTable(trialsData);
    renderCompareCharts(trialsData);
    renderCompareSummary(trialsData);
}

function renderCompareTable(trialsData) {
    const headersRow = document.getElementById('compare-table-headers');
    const tbody = document.getElementById('compare-metrics-tbody');
    if (!headersRow || !tbody) return;
    
    headersRow.innerHTML = '<th style="text-align: left; padding: 12px; font-weight: 600; width: 250px;">Variable / Métrica</th>';
    
    trialsData.forEach(trial => {
        headersRow.innerHTML += `
            <th style="text-align: center; padding: 12px; font-weight: 600; min-width: 160px; background: rgba(255,255,255,0.01); border-left: 1px solid rgba(255,255,255,0.05);">
                <div style="font-size: 0.95rem; color: #F8FAFC;">${escapeHTML(trial.nombre)}</div>
                <div style="font-size: 0.75rem; opacity: 0.5; font-weight: 400; margin-top: 0.25rem;">${trial.fecha}</div>
            </th>
        `;
    });
    
    const metrics = [
        { name: 'Dataset utilizado', explanation: 'Base de datos de pruebas (ej: dev o test).', key: 'dataset', format: v => v },
        { name: 'Total casos analizados', explanation: 'Cantidad total de funciones/scripts evaluados.', key: 'casos', format: v => v },
        { name: 'Acierto Detección (Vulnerable vs Seguro)', explanation: 'Porcentaje de archivos clasificados correctamente como vulnerables o seguros.', key: 'accuracyDet', format: v => `<strong style="color: #3B82F6;">${v}%</strong>` },
        { name: 'Acierto Clasificación OWASP', explanation: 'Porcentaje de acierto asignando la categoría correcta de vulnerabilidad (OWASP Top 10).', key: 'accuracyClas', format: v => `<strong style="color: #10B981;">${v}%</strong>` },
        { name: 'Sensibilidad / Recall', explanation: 'Porcentaje de vulnerabilidades reales que el agente logró detectar.', key: 'recall', format: v => `${v}%` },
        { name: 'Tasa de Falsos Positivos (FPR)', explanation: 'Porcentaje de código seguro que el agente alertó erróneamente como vulnerable.', key: 'fpr', format: v => `<span style="color: ${parseFloat(v) > 50 ? '#EF4444' : '#E2E8F0'}">${v}%</span>` },
        { name: 'Tasa de Falsos Negativos (FNR)', explanation: 'Porcentaje de vulnerabilidades reales que el agente omitió (no detectó).', key: 'fnr', format: v => `${v}%` },
        { name: 'Verdaderos Positivos (TP)', explanation: 'Casos vulnerables reales detectados correctamente.', key: 'tp', format: v => v },
        { name: 'Verdaderos Negativos (TN)', explanation: 'Casos seguros reales detectados correctamente.', key: 'tn', format: v => v },
        { name: 'Falsos Positivos (FP)', explanation: 'Casos seguros reales alertados falsamente como vulnerables.', key: 'fp', format: v => v },
        { name: 'Falsos Negativos (FN)', explanation: 'Casos vulnerables reales que no fueron detectados.', key: 'fn', format: v => v },
        { name: 'Tiempo Promedio por Caso', explanation: 'Duración promedio en segundos del análisis de cada archivo.', key: 'tiempo_promedio', format: v => v !== null && v !== undefined ? `${parseFloat(v).toFixed(2)} s` : '--' }
    ];
    
    tbody.innerHTML = '';
    metrics.forEach(metric => {
        const tr = document.createElement('tr');
        tr.style.borderBottom = '1px solid rgba(255,255,255,0.05)';
        
        let cells = `
            <td style="padding: 12px; vertical-align: top; width: 250px;">
                <div style="font-weight: 600; color: #F8FAFC; font-size: 0.9rem;">${escapeHTML(metric.name)}</div>
                <div style="font-size: 0.75rem; color: #94A3B8; margin-top: 0.25rem; font-weight: 400; line-height: 1.4; white-space: normal;">${escapeHTML(metric.explanation)}</div>
            </td>
        `;
        trialsData.forEach(trial => {
            const val = trial[metric.key];
            cells += `
                <td style="text-align: center; padding: 12px; vertical-align: top; border-left: 1px solid rgba(255,255,255,0.05); color: #E2E8F0;">
                    ${metric.format(val)}
                </td>
            `;
        });
        
        tr.innerHTML = cells;
        tbody.appendChild(tr);
    });
}

function renderCompareCharts(trialsData) {
    const ctxAcc = document.getElementById('compare-chart-accuracy');
    const ctxRates = document.getElementById('compare-chart-rates');
    if (!ctxAcc || !ctxRates) return;
    
    if (compareChartAccuracyInstance) compareChartAccuracyInstance.destroy();
    if (compareChartRatesInstance) compareChartRatesInstance.destroy();
    
    const labels = trialsData.map(t => t.nombre);
    
    compareChartAccuracyInstance = new Chart(ctxAcc.getContext('2d'), {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Acierto Detección (%)',
                    data: trialsData.map(t => parseFloat(t.accuracyDet)),
                    backgroundColor: 'rgba(59, 130, 246, 0.75)',
                    borderColor: '#3B82F6',
                    borderWidth: 1.5,
                    borderRadius: 4
                },
                {
                    label: 'Acierto Clasificación (%)',
                    data: trialsData.map(t => parseFloat(t.accuracyClas)),
                    backgroundColor: 'rgba(16, 185, 129, 0.75)',
                    borderColor: '#10B981',
                    borderWidth: 1.5,
                    borderRadius: 4
                },
                {
                    label: 'Sensibilidad / Recall (%)',
                    data: trialsData.map(t => parseFloat(t.recall)),
                    backgroundColor: 'rgba(139, 92, 246, 0.75)',
                    borderColor: '#8B5CF6',
                    borderWidth: 1.5,
                    borderRadius: 4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                    labels: { color: '#E2E8F0', font: { family: 'Inter, system-ui, sans-serif', size: 11 } }
                },
                tooltip: {
                    backgroundColor: '#1E293B',
                    titleColor: '#F8FAFC',
                    bodyColor: '#E2E8F0',
                    borderColor: 'rgba(255,255,255,0.1)',
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255,255,255,0.03)' },
                    ticks: { color: '#94A3B8', font: { size: 10 } }
                },
                y: {
                    min: 0,
                    max: 100,
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: { color: '#94A3B8', font: { size: 10 } }
                }
            }
        }
    });
    
    compareChartRatesInstance = new Chart(ctxRates.getContext('2d'), {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Falsos Positivos - FPR (%)',
                    data: trialsData.map(t => parseFloat(t.fpr)),
                    backgroundColor: 'rgba(239, 68, 68, 0.75)',
                    borderColor: '#EF4444',
                    borderWidth: 1.5,
                    borderRadius: 4
                },
                {
                    label: 'Falsos Negativos - FNR (%)',
                    data: trialsData.map(t => parseFloat(t.fnr)),
                    backgroundColor: 'rgba(245, 158, 11, 0.75)',
                    borderColor: '#F59E0B',
                    borderWidth: 1.5,
                    borderRadius: 4
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'top',
                    labels: { color: '#E2E8F0', font: { family: 'Inter, system-ui, sans-serif', size: 11 } }
                },
                tooltip: {
                    backgroundColor: '#1E293B',
                    titleColor: '#F8FAFC',
                    bodyColor: '#E2E8F0',
                    borderColor: 'rgba(255,255,255,0.1)',
                    borderWidth: 1
                }
            },
            scales: {
                x: {
                    grid: { color: 'rgba(255,255,255,0.03)' },
                    ticks: { color: '#94A3B8', font: { size: 10 } }
                },
                y: {
                    min: 0,
                    max: 100,
                    grid: { color: 'rgba(255,255,255,0.05)' },
                    ticks: { color: '#94A3B8', font: { size: 10 } }
                }
            }
        }
    });
}

function renderCompareSummary(trialsData) {
    const summaryCard = document.getElementById('compare-summary-card');
    const summaryContent = document.getElementById('compare-summary-content');
    if (!summaryCard || !summaryContent) return;

    if (trialsData.length !== 2) {
        summaryCard.style.display = 'none';
        return;
    }

    // Sort trials chronologically using dates or IDs
    const sorted = [...trialsData].sort((a, b) => {
        return String(a.fecha).localeCompare(String(b.fecha)) || (parseInt(a.id) - parseInt(b.id));
    });

    const oldTrial = sorted[0];
    const newTrial = sorted[1];

    const deltaAccDet = parseFloat(newTrial.accuracyDet) - parseFloat(oldTrial.accuracyDet);
    const deltaAccClas = parseFloat(newTrial.accuracyClas) - parseFloat(oldTrial.accuracyClas);
    const deltaFPR = parseFloat(newTrial.fpr) - parseFloat(oldTrial.fpr);
    const deltaFNR = parseFloat(newTrial.fnr) - parseFloat(oldTrial.fnr);
    const deltaTime = parseFloat(newTrial.tiempo_promedio || 0) - parseFloat(oldTrial.tiempo_promedio || 0);

    let html = `
        <p style="margin: 0; opacity: 0.8; font-size: 0.875rem; margin-bottom: 0.5rem;">
            Comparando <strong>${escapeHTML(oldTrial.nombre)}</strong> (anterior) vs. <strong>${escapeHTML(newTrial.nombre)}</strong> (nueva):
        </p>
        <ul style="margin: 0; padding-left: 1.2rem; display: flex; flex-direction: column; gap: 0.5rem; line-height: 1.5;">
    `;

    // 1. Detection accuracy
    if (deltaAccDet > 0) {
        html += `<li style="color: #10B981;">📈 El acierto de detección general <strong>aumentó un ${deltaAccDet.toFixed(1)}%</strong> (de ${oldTrial.accuracyDet}% a ${newTrial.accuracyDet}%).</li>`;
    } else if (deltaAccDet < 0) {
        html += `<li style="color: #EF4444;">📉 El acierto de detección general <strong>disminuyó un ${Math.abs(deltaAccDet).toFixed(1)}%</strong> (de ${oldTrial.accuracyDet}% a ${newTrial.accuracyDet}%).</li>`;
    } else {
        html += `<li style="color: #94A3B8;">⚪ El acierto de detección general se mantuvo <strong>igual</strong> (en ${newTrial.accuracyDet}%).</li>`;
    }

    // 2. Classification accuracy
    if (deltaAccClas > 0) {
        html += `<li style="color: #10B981;">🎯 El acierto de clasificación OWASP <strong>aumentó un ${deltaAccClas.toFixed(1)}%</strong> (de ${oldTrial.accuracyClas}% a ${newTrial.accuracyClas}%).</li>`;
    } else if (deltaAccClas < 0) {
        html += `<li style="color: #EF4444;">🎯 El acierto de clasificación OWASP <strong>disminuyó un ${Math.abs(deltaAccClas).toFixed(1)}%</strong> (de ${oldTrial.accuracyClas}% a ${newTrial.accuracyClas}%).</li>`;
    } else {
        html += `<li style="color: #94A3B8;">🎯 El acierto de clasificación OWASP se mantuvo <strong>igual</strong> (en ${newTrial.accuracyClas}%).</li>`;
    }

    // 3. False Positives (FPR) - decrease is good (green), increase is bad (red)
    if (deltaFPR < 0) {
        html += `<li style="color: #10B981;">🛡️ La tasa de falsos positivos (FPR) <strong>disminuyó un ${Math.abs(deltaFPR).toFixed(1)}%</strong> (de ${oldTrial.fpr}% a ${newTrial.fpr}%). ¡Menos falsas alarmas!</li>`;
    } else if (deltaFPR > 0) {
        html += `<li style="color: #EF4444;">⚠️ La tasa de falsos positivos (FPR) <strong>aumentó un ${deltaFPR.toFixed(1)}%</strong> (de ${oldTrial.fpr}% a ${newTrial.fpr}%).</li>`;
    } else {
        html += `<li style="color: #94A3B8;">🛡️ La tasa de falsos positivos (FPR) se mantuvo <strong>igual</strong> (en ${newTrial.fpr}%).</li>`;
    }

    // 4. False Negatives (FNR) - decrease is good (green), increase is bad (red)
    if (deltaFNR < 0) {
        html += `<li style="color: #10B981;">🔍 La tasa de falsos negativos (FNR / vulnerabilidades omitidas) <strong>disminuyó un ${Math.abs(deltaFNR).toFixed(1)}%</strong> (de ${oldTrial.fnr}% a ${newTrial.fnr}%).</li>`;
    } else if (deltaFNR > 0) {
        html += `<li style="color: #EF4444;">🔍 La tasa de falsos negativos (FNR / vulnerabilidades omitidas) <strong>aumentó un ${deltaFNR.toFixed(1)}%</strong> (de ${oldTrial.fnr}% a ${newTrial.fnr}%).</li>`;
    } else {
        html += `<li style="color: #94A3B8;">🔍 La tasa de falsos negativos (FNR) se mantuvo <strong>igual</strong> (en ${newTrial.fnr}%).</li>`;
    }

    // 5. Avg Time per case - decrease is good (green), increase is bad (red)
    if (oldTrial.tiempo_promedio && newTrial.tiempo_promedio) {
        if (deltaTime < 0) {
            html += `<li style="color: #10B981;">⚡ El tiempo promedio por caso <strong>disminuyó ${Math.abs(deltaTime).toFixed(2)}s</strong> (de ${parseFloat(oldTrial.tiempo_promedio).toFixed(2)}s a ${parseFloat(newTrial.tiempo_promedio).toFixed(2)}s).</li>`;
        } else if (deltaTime > 0) {
            html += `<li style="color: #EF4444;">⏳ El tiempo promedio por caso <strong>aumentó ${deltaTime.toFixed(2)}s</strong> (de ${parseFloat(oldTrial.tiempo_promedio).toFixed(2)}s a ${parseFloat(newTrial.tiempo_promedio).toFixed(2)}s).</li>`;
        } else {
            html += `<li style="color: #94A3B8;">⏳ El tiempo promedio por caso se mantuvo <strong>igual</strong> (en ${parseFloat(newTrial.tiempo_promedio).toFixed(2)}s).</li>`;
        }
    }

    html += `</ul>`;
    summaryContent.innerHTML = html;
    summaryCard.style.display = 'block';
}


