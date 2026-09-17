/**
 * Sentinel AML — Landing Page Scripts
 * Packaged as a standalone module to comply with strict Content-Security-Policy (CSP)
 */

(function () {
  'use strict';

  // --- Modal Controllers ---
  function openVideoWalkthroughModal() {
    const modal = document.getElementById('video-walkthrough-modal');
    if (modal) {
      modal.classList.remove('hidden');
    }
  }

  function closeVideoWalkthroughModal() {
    const modal = document.getElementById('video-walkthrough-modal');
    if (modal) {
      modal.classList.add('hidden');
    }
  }

  function toggleMobileMenu() {
    const menu = document.getElementById('mobile-menu');
    if (menu) {
      menu.classList.toggle('hidden');
    }
  }

  // Expose to window for backwards compatibility if needed
  window.openVideoWalkthroughModal = openVideoWalkthroughModal;
  window.closeVideoWalkthroughModal = closeVideoWalkthroughModal;
  window.toggleMobileMenu = toggleMobileMenu;

  // --- Three.js 3D Financial Network Topology ---
  let scene, camera, renderer, controls;
  let nodesGroup, arcsGroup, particlesGroup;
  let autoRotate = true;
  let raycaster, mouse;
  let nodeMeshes = [];

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
    const height = container.clientHeight || 480;

    // 1. Scene Setup
    scene = new THREE.Scene();
    scene.background = new THREE.Color(0x1B1F2B);

    // 2. Camera
    camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
    camera.position.set(0, 30, 110);

    // 3. Renderer
    renderer = new THREE.WebGLRenderer({ antialias: true });
    renderer.setSize(width, height);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    container.innerHTML = '';
    container.appendChild(renderer.domElement);

    // 4. Controls
    if (typeof THREE.OrbitControls !== 'undefined') {
      controls = new THREE.OrbitControls(camera, renderer.domElement);
      controls.enableDamping = true;
      controls.dampingFactor = 0.05;
      controls.maxDistance = 180;
      controls.minDistance = 40;
    }

    // 5. Lights
    const ambientLight = new THREE.AmbientLight(0xffffff, 0.8);
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
    const globeGeo = new THREE.SphereGeometry(50, 24, 24);
    const globeMat = new THREE.MeshBasicMaterial({
      color: 0x2B3040,
      wireframe: true,
      transparent: true,
      opacity: 0.25
    });
    const globeMesh = new THREE.Mesh(globeGeo, globeMat);
    scene.add(globeMesh);

    // 8. Create Nodes
    nodeMeshes = [];
    financialNodes.forEach((data) => {
      let nodeColor = 0x4C7A5E; // low green
      if (data.type === 'high') nodeColor = 0xC1443B; // high red
      if (data.type === 'med') nodeColor = 0xC98A2E;  // med amber

      const sphereGeo = new THREE.SphereGeometry(data.type === 'high' ? 3.5 : 2.5, 16, 16);
      const sphereMat = new THREE.MeshStandardMaterial({
        color: nodeColor,
        roughness: 0.3,
        metalness: 0.2
      });
      const mesh = new THREE.Mesh(sphereGeo, sphereMat);
      mesh.position.set(data.x, data.y, data.z);
      mesh.userData = data;
      nodesGroup.add(mesh);
      nodeMeshes.push(mesh);

      // Halo Ring around High-Risk Nodes
      if (data.type === 'high') {
        const ringGeo = new THREE.RingGeometry(4.5, 5.2, 24);
        const ringMat = new THREE.MeshBasicMaterial({ color: 0xC1443B, side: THREE.DoubleSide, transparent: true, opacity: 0.7 });
        const ringMesh = new THREE.Mesh(ringGeo, ringMat);
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
      const points = curve.getPoints(36);
      const lineGeo = new THREE.BufferGeometry().setFromPoints(points);

      let arcColor = 0x3D5A80;
      if (conn.type === 'high') arcColor = 0xC1443B;
      if (conn.type === 'med') arcColor = 0xC98A2E;

      const lineMat = new THREE.LineBasicMaterial({
        color: arcColor,
        transparent: true,
        opacity: conn.type === 'high' ? 0.85 : 0.45,
        linewidth: conn.type === 'high' ? 2 : 1
      });

      const arcLine = new THREE.Line(lineGeo, lineMat);
      arcLine.userData = { curve: curve, type: conn.type };
      arcsGroup.add(arcLine);

      // Traveling pulse particle
      const particleGeo = new THREE.SphereGeometry(0.8, 8, 8);
      const particleMat = new THREE.MeshBasicMaterial({ color: arcColor });
      const particleMesh = new THREE.Mesh(particleGeo, particleMat);
      particleMesh.userData = { curve: curve, t: Math.random(), speed: 0.005 + Math.random() * 0.005 };
      particlesGroup.add(particleMesh);
    });

    // 10. Raycaster for Interactive Hover
    raycaster = new THREE.Raycaster();
    mouse = new THREE.Vector2();

    container.addEventListener('mousemove', onMouseMove, false);
    window.addEventListener('resize', onWindowResize, false);

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
        const colorClass = d.type === 'high' ? '#C1443B' : (d.type === 'med' ? '#C98A2E' : '#4C7A5E');
        readout.innerHTML = `<span style="color:${colorClass}">AUDIT TARGET: ${d.name} (${d.code}) · Risk: ${d.risk}</span>`;
      }
    } else {
      if (readout) readout.innerText = "Hover over any banking node to audit...";
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
      readout.innerHTML = `<span style="color:#C1443B; font-weight:bold;">ALERT ISOLATION: Cayman Islands &amp; Panama Secrecy Shell Ring Active</span>`;
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

    if (autoRotate && scene) {
      scene.rotation.y += 0.002;
    }

    if (controls) {
      controls.update();
    }

    if (particlesGroup) {
      particlesGroup.children.forEach((p) => {
        p.userData.t += p.userData.speed;
        if (p.userData.t > 1) p.userData.t = 0;
        const pos = p.userData.curve.getPoint(p.userData.t);
        p.position.copy(pos);
      });
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

    // 2. Initialize Three.js Graph
    initThreeJS();

    // 3. Bind Modal Open Triggers
    document.querySelectorAll('[data-action="open-video-modal"]').forEach((el) => {
      el.addEventListener('click', (e) => {
        e.preventDefault();
        openVideoWalkthroughModal();
      });
    });

    // 4. Bind Modal Close Triggers
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

    // 5. Bind Mobile Menu Trigger & Links
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

    // 6. Bind 3D Canvas Controls
    const btnRotate = document.getElementById('btn-3d-rotate');
    if (btnRotate) {
      btnRotate.addEventListener('click', toggle3DRotation);
    }

    const btnIsolate = document.getElementById('btn-3d-isolate');
    if (btnIsolate) {
      btnIsolate.addEventListener('click', isolateHighRiskNodes);
    }

    const btnReset = document.getElementById('btn-3d-reset');
    if (btnReset) {
      btnReset.addEventListener('click', reset3DCamera);
    }

    // 7. Bind Range Slider for Fuzzy Sensitivity
    const threshSlider = document.getElementById('demo-thresh-slider');
    const threshLabel = document.getElementById('demo-thresh-label');
    if (threshSlider && threshLabel) {
      threshSlider.addEventListener('input', function () {
        threshLabel.textContent = `${this.value}% Match Limit`;
      });
    }

    // 8. Global Keyboard Shortcuts
    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeVideoWalkthroughModal();
      }
    });
  });

})();
