/**
 * Sentinel AML — Landing Page Scripts
 * Packaged as a standalone module to comply with strict Content-Security-Policy (CSP)
 * Optimized for Core Web Vitals (INP / Main-Thread Budget / Zero Offscreen GPU Drain)
 */

(function () {
  'use strict';

  // --- Modal & Mobile Navigation Controllers ---
  function openVideoWalkthroughModal() {
    const modal = document.getElementById('video-walkthrough-modal');
    if (modal) {
      modal.classList.remove('hidden');
      modal.classList.add('flex');
    }
  }

  function closeVideoWalkthroughModal() {
    const modal = document.getElementById('video-walkthrough-modal');
    if (modal) {
      modal.classList.add('hidden');
      modal.classList.remove('flex');
    }
  }

  function toggleMobileMenu() {
    const menu = document.getElementById('mobile-menu');
    if (menu) {
      const isHidden = menu.classList.toggle('hidden');
      document.querySelectorAll('[data-action="toggle-mobile-menu"]').forEach((btn) => {
        btn.setAttribute('aria-expanded', String(!isHidden));
      });
    }
  }

  window.openVideoWalkthroughModal = openVideoWalkthroughModal;
  window.closeVideoWalkthroughModal = closeVideoWalkthroughModal;
  window.toggleMobileMenu = toggleMobileMenu;

  // --- Sentinels Real-Time Global Laundering Counter (Reference 3) ---
  function initGlobalLaunderingCounter() {
    const counterEl = document.getElementById('global-laundered-counter');
    if (!counterEl) return;

    const baseAmount = 213239;
    // UNODC ~$2T/year estimate (~$63,419/sec globally); paced smoothly at 10Hz
    const ratePerSecond = 14850;
    const startTimestamp = performance.now();
    let isCounterVisible = true;

    if ('IntersectionObserver' in window) {
      const obs = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          isCounterVisible = entry.isIntersecting;
        });
      }, { threshold: 0.05 });
      obs.observe(counterEl);
    }

    setInterval(() => {
      if (!isCounterVisible || document.hidden) return;
      const elapsedSeconds = (performance.now() - startTimestamp) / 1000;
      const currentTotal = Math.floor(baseAmount + elapsedSeconds * ratePerSecond);
      counterEl.textContent = '$' + currentTotal.toLocaleString('en-US');
    }, 120);
  }

  // --- Three.js 3D Financial Network Topology (Viewport-Aware & Zero-GC Loop) ---
  let scene, camera, renderer, controls;
  let nodesGroup, arcsGroup, particlesGroup;
  let autoRotate = true;
  let is3DViewportVisible = false;
  let raycaster, mouse;
  let nodeMeshes = [];
  let tempVec3 = null;

  const financialNodes = [
    { name: "New York Fedwire Clearing", city: "US", x: -45, y: 15, z: 10, type: "low", code: "US-NYC", risk: "12%" },
    { name: "London SWIFT Hub", city: "GB", x: -10, y: 30, z: 15, type: "low", code: "GB-LON", risk: "14%" },
    { name: "Zurich Private Banking", city: "CH", x: 5, y: 25, z: -5, type: "low", code: "CH-ZRH", risk: "18%" },
    { name: "Frankfurt SEPA Core", city: "DE", x: 10, y: 28, z: 10, type: "low", code: "DE-FRA", risk: "15%" },
    { name: "Cayman Islands Secrecy Shell (Tobias Varga)", city: "KY", x: -35, y: -5, z: 35, type: "high", code: "KY-GCM", risk: "92%" },
    { name: "Panama Maritime Holding Corp", city: "PA", x: -30, y: -15, z: 20, type: "high", code: "PA-PTY", risk: "88%" },
    { name: "BVI Virtual Asset Onramp", city: "VG", x: -25, y: -8, z: 30, type: "med", code: "VG-TDA", risk: "76%" },
    { name: "Singapore Payment Aggregator", city: "SG", x: 45, y: -10, z: -25, type: "med", code: "SG-SIN", risk: "68%" },
    { name: "Tokyo Trade Settlement", city: "JP", x: 60, y: 15, z: -15, type: "low", code: "JP-TYO", risk: "10%" }
  ];

  const connections = [
    { from: 0, to: 4, type: "high" }, // NYC -> Cayman (flagged)
    { from: 1, to: 4, type: "high" }, // London -> Cayman (flagged)
    { from: 4, to: 5, type: "high" }, // Cayman -> Panama (structuring ring)
    { from: 0, to: 1, type: "low" },  // NYC -> London (routine)
    { from: 1, to: 2, type: "low" },  // London -> Zurich
    { from: 2, to: 3, type: "low" },  // Zurich -> Frankfurt
    { from: 3, to: 6, type: "med" },  // Frankfurt -> BVI Onramp
    { from: 6, to: 7, type: "med" },  // BVI -> Singapore
    { from: 7, to: 8, type: "low" }   // Singapore -> Tokyo
  ];

  function initThreeJS() {
    const container = document.getElementById('threejs-canvas-wrapper');
    if (!container || typeof THREE === 'undefined') return;

    const width = container.clientWidth || 800;
    const height = container.clientHeight || 460;
    tempVec3 = new THREE.Vector3();

    // 1. Scene Setup
    scene = new THREE.Scene();
    scene.background = new THREE.Color(0x1B1F2B);

    // 2. Camera
    camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(0, 30, 110);

    // 3. Renderer with WebGL Detection Fallback
    try {
      renderer = new THREE.WebGLRenderer({ antialias: true, powerPreference: 'high-performance' });
      renderer.setSize(width, height);
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
      container.innerHTML = '';
      container.appendChild(renderer.domElement);
    } catch (err) {
      console.warn('WebGL initialization failed, falling back to static visual representation:', err);
      container.innerHTML = '<div class="p-8 text-center text-slate-300 font-mono text-xs flex flex-col items-center justify-center h-full space-y-2"><div class="text-[#C98A2E] font-bold">● High-Res Vector Topology Mode Active</div><div class="text-slate-400 max-w-sm">WebGL is unavailable or disabled on this device. SWIFT and Fedwire node telemetry continues to stream synchronously.</div></div>';
      return;
    }

    // 4. Controls
    if (typeof THREE.OrbitControls !== 'undefined') {
      controls = new THREE.OrbitControls(camera, renderer.domElement);
      controls.enableDamping = true;
      controls.dampingFactor = 0.05;
      controls.maxDistance = 180;
      controls.minDistance = 40;
    }

    // 5. Lights
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.85);
    scene.add(ambientLight);

    const dirLight = new THREE.DirectionalLight(0xffffff, 1.2);
    dirLight.position.set(20, 50, 40);
    scene.add(dirLight);

    // 6. Groups
    nodesGroup = new THREE.Group();
    arcsGroup = new THREE.Group();
    particlesGroup = new THREE.Group();
    scene.add(nodesGroup);
    scene.add(arcsGroup);
    scene.add(particlesGroup);

    // 7. Ambient Lattice Wireframe Globe
    const globeGeo = new THREE.SphereGeometry(50, 20, 20);
    const globeMat = new THREE.MeshBasicMaterial({
      color: 0x2B3040,
      wireframe: true,
      transparent: true,
      opacity: 0.25
    });
    scene.add(new THREE.Mesh(globeGeo, globeMat));

    // 8. Shared Geometries for Nodes & Particles (reduces GPU memory)
    const highRiskSphereGeo = new THREE.SphereGeometry(3.5, 16, 16);
    const stdSphereGeo = new THREE.SphereGeometry(2.5, 16, 16);
    const sharedParticleGeo = new THREE.SphereGeometry(0.8, 8, 8);
    const haloRingGeo = new THREE.RingGeometry(4.5, 5.2, 24);

    nodeMeshes = [];
    financialNodes.forEach((data) => {
      let nodeColor = 0x4C7A5E;
      if (data.type === 'high') nodeColor = 0xC1443B;
      if (data.type === 'med') nodeColor = 0xC98A2E;

      const sphereMat = new THREE.MeshStandardMaterial({
        color: nodeColor,
        roughness: 0.3,
        metalness: 0.2
      });
      const mesh = new THREE.Mesh(data.type === 'high' ? highRiskSphereGeo : stdSphereGeo, sphereMat);
      mesh.position.set(data.x, data.y, data.z);
      mesh.userData = data;
      nodesGroup.add(mesh);
      nodeMeshes.push(mesh);

      if (data.type === 'high') {
        const ringMat = new THREE.MeshBasicMaterial({ color: 0xC1443B, side: THREE.DoubleSide, transparent: true, opacity: 0.7 });
        const ringMesh = new THREE.Mesh(haloRingGeo, ringMat);
        ringMesh.position.set(data.x, data.y, data.z);
        ringMesh.lookAt(camera.position);
        nodesGroup.add(ringMesh);
      }
    });

    // 9. Curved 3D Quadratic Transfer Arcs
    connections.forEach((conn) => {
      const startNode = financialNodes[conn.from];
      const endNode = financialNodes[conn.to];

      const startVec = new THREE.Vector3(startNode.x, startNode.y, startNode.z);
      const endVec = new THREE.Vector3(endNode.x, endNode.y, endNode.z);

      const midVec = new THREE.Vector3().addVectors(startVec, endVec).multiplyScalar(0.5);
      const distance = startVec.distanceTo(endVec);
      midVec.y += distance * 0.35;

      const curve = new THREE.QuadraticBezierCurve3(startVec, midVec, endVec);
      const points = curve.getPoints(32);
      const lineGeo = new THREE.BufferGeometry().setFromPoints(points);

      let arcColor = 0x3D5A80;
      if (conn.type === 'high') arcColor = 0xC1443B;
      if (conn.type === 'med') arcColor = 0xC98A2E;

      const lineMat = new THREE.LineBasicMaterial({
        color: arcColor,
        transparent: true,
        opacity: conn.type === 'high' ? 0.85 : 0.45
      });

      const arcLine = new THREE.Line(lineGeo, lineMat);
      arcLine.userData = { curve: curve, type: conn.type };
      arcsGroup.add(arcLine);

      const particleMat = new THREE.MeshBasicMaterial({ color: arcColor });
      const particleMesh = new THREE.Mesh(sharedParticleGeo, particleMat);
      particleMesh.userData = { curve: curve, t: Math.random(), speed: 0.004 + Math.random() * 0.004 };
      particlesGroup.add(particleMesh);
    });

    // 10. Raycaster for Interactive Hover
    raycaster = new THREE.Raycaster();
    mouse = new THREE.Vector2();

    container.addEventListener('mousemove', onMouseMove, { passive: true });
    window.addEventListener('resize', onWindowResize, { passive: true });

    // Pause WebGL render loop when offscreen to keep main thread & GPU cool
    if ('IntersectionObserver' in window) {
      const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry) => {
          is3DViewportVisible = entry.isIntersecting;
        });
      }, { threshold: 0.05 });
      observer.observe(container);
    } else {
      is3DViewportVisible = true;
    }

    // Render initial frame immediately
    if (renderer && scene && camera) {
      renderer.render(scene, camera);
    }
    animate();
  }

  function onMouseMove(event) {
    const container = document.getElementById('threejs-canvas-wrapper');
    if (!container || !camera) return;
    const rect = container.getBoundingClientRect();
    mouse.x = ((event.clientX - rect.left) / container.clientWidth) * 2 - 1;
    mouse.y = -((event.clientY - rect.top) / container.clientHeight) * 2 + 1;

    raycaster.setFromCamera(mouse, camera);
    const intersects = raycaster.intersectObjects(nodeMeshes);

    const readout = document.getElementById('threejs-hover-readout');
    if (intersects.length > 0) {
      const d = intersects[0].object.userData;
      if (readout) {
        const colorClass = d.type === 'high' ? '#F87171' : (d.type === 'med' ? '#F4D078' : '#34D399');
        readout.innerHTML = `<span style="color:${colorClass}">AUDIT TARGET: ${d.name} (${d.code}) · Risk: ${d.risk}</span>`;
      }
    } else if (readout) {
      readout.innerText = "Hover over any banking node to audit...";
    }
  }

  function onWindowResize() {
    const container = document.getElementById('threejs-canvas-wrapper');
    if (!container || !renderer || !camera) return;
    camera.aspect = container.clientWidth / container.clientHeight;
    camera.updateProjectionMatrix();
    renderer.setSize(container.clientWidth, container.clientHeight);
  }

  function toggle3DRotation() {
    autoRotate = !autoRotate;
    const btn = document.getElementById('btn-3d-rotate');
    if (btn) {
      btn.innerHTML = `<i data-lucide="rotate-cw" class="w-3.5 h-3.5"></i> <span>Auto-Rotate: ${autoRotate ? 'ON' : 'OFF'}</span>`;
    }
    if (window.lucide) window.lucide.createIcons();
  }

  function isolateHighRiskNodes() {
    autoRotate = false;
    const btn = document.getElementById('btn-3d-rotate');
    if (btn) {
      btn.innerHTML = `<i data-lucide="rotate-cw" class="w-3.5 h-3.5"></i> <span>Auto-Rotate: OFF</span>`;
    }
    if (window.lucide) window.lucide.createIcons();

    if (camera) camera.position.set(-45, 10, 80);
    if (controls) controls.target.set(-35, -10, 25);

    const readout = document.getElementById('threejs-hover-readout');
    if (readout) {
      readout.innerHTML = `<span style="color:#F87171; font-weight:bold;">ALERT ISOLATION: Cayman Islands &amp; Panama Secrecy Shell Ring Active</span>`;
    }
  }

  function reset3DCamera() {
    if (camera) camera.position.set(0, 30, 110);
    if (controls) controls.target.set(0, 0, 0);
    autoRotate = true;
    const btn = document.getElementById('btn-3d-rotate');
    if (btn) {
      btn.innerHTML = `<i data-lucide="rotate-cw" class="w-3.5 h-3.5"></i> <span>Auto-Rotate: ON</span>`;
    }
    if (window.lucide) window.lucide.createIcons();
  }

  function animate() {
    requestAnimationFrame(animate);

    if (!is3DViewportVisible || document.hidden) return;

    if (autoRotate && scene) {
      scene.rotation.y += 0.002;
    }

    if (controls) {
      controls.update();
    }

    if (particlesGroup && tempVec3) {
      const children = particlesGroup.children;
      for (let i = 0; i < children.length; i++) {
        const p = children[i];
        p.userData.t += p.userData.speed;
        if (p.userData.t > 1) p.userData.t = 0;
        p.userData.curve.getPoint(p.userData.t, tempVec3);
        p.position.copy(tempVec3);
      }
    }

    if (renderer && scene && camera) {
      renderer.render(scene, camera);
    }
  }

  // --- Setup Event Listeners Unobtrusively (CSP-Compliant) ---
  document.addEventListener('DOMContentLoaded', () => {
    // 1. Initialize Lucide Icons
    if (window.lucide) {
      window.lucide.createIcons();
    }

    // 2. Initialize Live Global Laundering Counter
    initGlobalLaunderingCounter();

    // 3. Initialize Three.js Graph
    initThreeJS();

    // 4. Bind Modal Open Triggers
    document.querySelectorAll('[data-action="open-video-modal"]').forEach((el) => {
      el.addEventListener('click', (e) => {
        e.preventDefault();
        openVideoWalkthroughModal();
      });
    });

    // 5. Bind Modal Close Triggers
    document.querySelectorAll('[data-action="close-video-modal"]').forEach((el) => {
      el.addEventListener('click', (e) => {
        e.preventDefault();
        closeVideoWalkthroughModal();
      });
    });

    const videoModal = document.getElementById('video-walkthrough-modal');
    if (videoModal) {
      videoModal.addEventListener('click', (e) => {
        if (e.target === videoModal) {
          closeVideoWalkthroughModal();
        }
      });
    }

    // 6. Bind Mobile Menu Trigger & Links
    document.querySelectorAll('[data-action="toggle-mobile-menu"]').forEach((el) => {
      el.addEventListener('click', (e) => {
        e.preventDefault();
        toggleMobileMenu();
      });
    });

    document.querySelectorAll('#mobile-menu a').forEach((link) => {
      link.addEventListener('click', () => {
        const menu = document.getElementById('mobile-menu');
        if (menu && !menu.classList.contains('hidden')) {
          menu.classList.add('hidden');
        }
      });
    });

    // 7. Bind 3D Canvas Controls
    const btnRotate = document.getElementById('btn-3d-rotate');
    if (btnRotate) btnRotate.addEventListener('click', toggle3DRotation);

    const btnIsolate = document.getElementById('btn-3d-isolate');
    if (btnIsolate) btnIsolate.addEventListener('click', isolateHighRiskNodes);

    const btnReset = document.getElementById('btn-3d-reset');
    if (btnReset) btnReset.addEventListener('click', reset3DCamera);

    // 8. Bind Range Slider for Phonetic KYC / OFAC SDN Fuzzy Sensitivity
    const threshSlider = document.getElementById('demo-thresh-slider');
    const threshLabel = document.getElementById('demo-thresh-label');
    const threshResult = document.getElementById('demo-thresh-result');
    if (threshSlider && threshLabel) {
      const updateDemoMatch = () => {
        const limit = Number.parseInt(threshSlider.value, 10);
        threshLabel.textContent = `${limit}% Match Limit`;
        if (threshResult) {
          const sampleScore = 92;
          if (sampleScore >= limit) {
            threshResult.textContent = `→ OFAC SDN Blocklist Hit (${sampleScore}% ≥ ${limit}%)`;
            threshResult.className = 'text-risk-high block font-semibold';
          } else {
            threshResult.textContent = `→ Cleared Below Threshold (${sampleScore}% < ${limit}%)`;
            threshResult.className = 'text-risk-low block font-semibold';
          }
        }
      };
      threshSlider.addEventListener('input', updateDemoMatch);
      updateDemoMatch();
    }

    // 9. Global Keyboard Shortcuts
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeVideoWalkthroughModal();
      }
    });
  });

})();
