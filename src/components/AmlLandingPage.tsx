import React, { useState, useEffect, useRef, useMemo, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  ShieldAlert,
  Play,
  PlayCircle,
  ArrowRight,
  Zap,
  Activity,
  Network,
  ScanFace,
  PieChart,
  Archive,
  Lock,
  Key,
  Database,
  Server,
  Check,
  X,
  RotateCw,
  AlertOctagon,
  Maximize2,
  Volume2,
  Menu,
  FileText,
  Sliders,
  Radio,
  Search,
  CheckCircle2,
  AlertTriangle,
  ChevronRight,
  Info,
  Layers,
  BarChart3,
  Pause
} from 'lucide-react';

/**
 * Institutional AML Sentinel Landing Page Gateway
 * Architecture: React + Tailwind CSS + Framer Motion + Lucide React + Three.js
 * Palette:
 *  - #1B1F2B (charcoal-navy sidebar, not pure black)
 *  - #ECE7DD (warm paper canvas)
 *  - #FFFFFF (panel surface)
 *  - #DAD3C3 (panel border edge)
 *  - #C1443B (risk/block red)
 *  - #C98A2E (escalate amber)
 *  - #4C7A5E (approve green)
 *  - #3D5A80 (active/link blue)
 *  - #22262E (ink text)
 */

export interface FinancialNode {
  id: number;
  name: string;
  code: string;
  city: string;
  x: number;
  y: number;
  z: number;
  type: 'low' | 'med' | 'high';
  risk: string;
  swiftBic: string;
  dailyVolume: string;
  uboStatus: string;
}

const FINANCIAL_NODES: FinancialNode[] = [
  { id: 0, name: 'New York Fedwire Clearing', city: 'US', x: -45, y: 15, z: 10, type: 'low', code: 'US-NYC', risk: '12%', swiftBic: 'FEDWUS33', dailyVolume: '$14.2B', uboStatus: 'Regulated Sovereign Clearing' },
  { id: 1, name: 'London SWIFT Hub', city: 'GB', x: -10, y: 30, z: 15, type: 'low', code: 'GB-LON', risk: '14%', swiftBic: 'SWFTGB22', dailyVolume: '$9.8B', uboStatus: 'Bank of England Member' },
  { id: 2, name: 'Zurich Private Banking', city: 'CH', x: 5, y: 25, z: -5, type: 'low', code: 'CH-ZRH', risk: '18%', swiftBic: 'ZURICHCH', dailyVolume: '$4.1B', uboStatus: 'FINMA Tier-1 License' },
  { id: 3, name: 'Frankfurt SEPA Core', city: 'DE', x: 10, y: 28, z: 10, type: 'low', code: 'DE-FRA', risk: '15%', swiftBic: 'SEPADEMM', dailyVolume: '$8.5B', uboStatus: 'Bundesbank Member' },
  { id: 4, name: 'Cayman Secrecy Shell (Tobias Varga)', city: 'KY', x: -35, y: -5, z: 35, type: 'high', code: 'KY-GCM', risk: '92%', swiftBic: 'SHLLKYXX', dailyVolume: '$840M', uboStatus: 'Nominee Director (60% Offshore)' },
  { id: 5, name: 'Panama Maritime Holding Corp', city: 'PA', x: -30, y: -15, z: 20, type: 'high', code: 'PA-PTY', risk: '88%', swiftBic: 'PMRMPA22', dailyVolume: '$520M', uboStatus: 'Bearer Shares Identified' },
  { id: 6, name: 'BVI Virtual Asset Onramp', city: 'VG', x: -25, y: -8, z: 30, type: 'med', code: 'VG-TDA', risk: '76%', swiftBic: 'BVIVAG11', dailyVolume: '$1.2B', uboStatus: 'Unlicensed VASP Aggregator' },
  { id: 7, name: 'Singapore Payment Aggregator', city: 'SG', x: 45, y: -10, z: -25, type: 'med', code: 'SG-SIN', risk: '68%', swiftBic: 'SGPAYSGS', dailyVolume: '$3.4B', uboStatus: 'MAS MPI Regulated Entity' },
  { id: 8, name: 'Tokyo Trade Settlement', city: 'JP', x: 60, y: 15, z: -15, type: 'low', code: 'JP-TYO', risk: '10%', swiftBic: 'BOJTJPJT', dailyVolume: '$6.7B', uboStatus: 'BOJ Core Clearing System' },
];

const CONNECTIONS = [
  { from: 0, to: 4, type: 'high', label: 'Wire Structuring ($9,480.00)' },
  { from: 1, to: 4, type: 'high', label: 'Layering Wire Corridor' },
  { from: 4, to: 5, type: 'high', label: 'Shell Entity Distribution' },
  { from: 0, to: 1, type: 'low', label: 'Routine Correspondent Flow' },
  { from: 1, to: 2, type: 'low', label: 'Treasury Clearing' },
  { from: 2, to: 3, type: 'low', label: 'Interbank Liquidity' },
  { from: 3, to: 6, type: 'med', label: 'VASP Gateway Transfer' },
  { from: 6, to: 7, type: 'med', label: 'Aggregator Transit' },
  { from: 7, to: 8, type: 'low', label: 'Commercial Settlement' },
];

// ─────────────────────────────────────────────────────────────
// THREE.JS INTERACTIVE 3D MONEY FLOW COMPONENT WITH 2D FALLBACK
// ─────────────────────────────────────────────────────────────
const ThreeJsMoneyFlowGraph: React.FC<{
  onSelectNode: (node: FinancialNode) => void;
  selectedNode: FinancialNode | null;
}> = ({ onSelectNode, selectedNode }) => {
  const mountRef = useRef<HTMLDivElement | null>(null);
  const [autoRotate, setAutoRotate] = useState(true);
  const [hoveredNode, setHoveredNode] = useState<FinancialNode | null>(null);
  const [webGlAvailable, setWebGlAvailable] = useState<boolean>(true);
  const autoRotateRef = useRef(true);
  const cameraRef = useRef<any>(null);
  const sceneRef = useRef<any>(null);

  useEffect(() => {
    autoRotateRef.current = autoRotate;
  }, [autoRotate]);

  // Check WebGL support safely
  const checkWebGL = useCallback(() => {
    try {
      const canvas = document.createElement('canvas');
      return !!(window.WebGLRenderingContext && (canvas.getContext('webgl') || canvas.getContext('experimental-webgl')));
    } catch {
      return false;
    }
  }, []);

  useEffect(() => {
    const isSupported = checkWebGL();
    const THREE = (window as any).THREE;
    if (!isSupported || !THREE) {
      setWebGlAvailable(false);
      return;
    }

    const container = mountRef.current;
    if (!container) return;

    let animId: number;
    let renderer: any = null;

    try {
      const width = container.clientWidth || 800;
      const height = container.clientHeight || 480;

      const scene = new THREE.Scene();
      sceneRef.current = scene;
      scene.background = new THREE.Color(0x1B1F2B);

      const camera = new THREE.PerspectiveCamera(45, width / height, 0.1, 1000);
      camera.position.set(0, 30, 110);
      cameraRef.current = camera;

      renderer = new THREE.WebGLRenderer({ antialias: true, powerPreference: 'high-performance' });
      renderer.setSize(width, height);
      renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));

      container.innerHTML = '';
      container.appendChild(renderer.domElement);

      // Orbit Controls if available
      let controls: any = null;
      const OrbitControls = (window as any).THREE?.OrbitControls || (THREE as any).OrbitControls;
      if (OrbitControls) {
        controls = new OrbitControls(camera, renderer.domElement);
        controls.enableDamping = true;
        controls.dampingFactor = 0.05;
        controls.maxDistance = 180;
        controls.minDistance = 40;
      }

      // Lights
      const ambientLight = new THREE.AmbientLight(0xffffff, 0.85);
      scene.add(ambientLight);

      const dirLight = new THREE.DirectionalLight(0xffffff, 1.2);
      dirLight.position.set(20, 50, 40);
      scene.add(dirLight);

      const nodesGroup = new THREE.Group();
      const arcsGroup = new THREE.Group();
      const particlesGroup = new THREE.Group();
      scene.add(nodesGroup);
      scene.add(arcsGroup);
      scene.add(particlesGroup);

      // Ambient wireframe globe
      const globeGeo = new THREE.SphereGeometry(50, 24, 24);
      const globeMat = new THREE.MeshBasicMaterial({
        color: 0x2B3040,
        wireframe: true,
        transparent: true,
        opacity: 0.25,
      });
      const globeMesh = new THREE.Mesh(globeGeo, globeMat);
      scene.add(globeMesh);

      // Create Nodes
      const nodeMeshes: any[] = [];
      FINANCIAL_NODES.forEach((node) => {
        let nodeColor = 0x4C7A5E;
        if (node.type === 'high') nodeColor = 0xC1443B;
        if (node.type === 'med') nodeColor = 0xC98A2E;

        const sphereGeo = new THREE.SphereGeometry(node.type === 'high' ? 3.8 : 2.6, 16, 16);
        const sphereMat = new THREE.MeshStandardMaterial({
          color: nodeColor,
          roughness: 0.3,
          metalness: 0.2,
        });
        const mesh = new THREE.Mesh(sphereGeo, sphereMat);
        mesh.position.set(node.x, node.y, node.z);
        mesh.userData = node;
        nodesGroup.add(mesh);
        nodeMeshes.push(mesh);

        // Threat halo for critical risks
        if (node.type === 'high') {
          const ringGeo = new THREE.RingGeometry(4.8, 5.5, 24);
          const ringMat = new THREE.MeshBasicMaterial({
            color: 0xC1443B,
            side: THREE.DoubleSide,
            transparent: true,
            opacity: 0.75,
          });
          const ringMesh = new THREE.Mesh(ringGeo, ringMat);
          ringMesh.position.set(node.x, node.y, node.z);
          ringMesh.lookAt(camera.position);
          nodesGroup.add(ringMesh);
        }
      });

      // Connections & Traveling Pulse particles
      CONNECTIONS.forEach((conn) => {
        const startNode = FINANCIAL_NODES[conn.from];
        const endNode = FINANCIAL_NODES[conn.to];

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
          linewidth: conn.type === 'high' ? 2 : 1,
        });

        const arcLine = new THREE.Line(lineGeo, lineMat);
        arcsGroup.add(arcLine);

        // Pulse particle
        const particleGeo = new THREE.SphereGeometry(0.8, 8, 8);
        const particleMat = new THREE.MeshBasicMaterial({ color: arcColor });
        const particleMesh = new THREE.Mesh(particleGeo, particleMat);
        particleMesh.userData = { curve, t: Math.random(), speed: 0.005 + Math.random() * 0.005 };
        particlesGroup.add(particleMesh);
      });

      // Raycaster for Hover and Click
      const raycaster = new THREE.Raycaster();
      const mouse = new THREE.Vector2();

      const getIntersects = (event: MouseEvent) => {
        const rect = container.getBoundingClientRect();
        mouse.x = ((event.clientX - rect.left) / container.clientWidth) * 2 - 1;
        mouse.y = -((event.clientY - rect.top) / container.clientHeight) * 2 + 1;
        raycaster.setFromCamera(mouse, camera);
        return raycaster.intersectObjects(nodeMeshes);
      };

      const handleMouseMove = (event: MouseEvent) => {
        const intersects = getIntersects(event);
        if (intersects.length > 0) {
          setHoveredNode(intersects[0].object.userData);
          container.style.cursor = 'pointer';
        } else {
          setHoveredNode(null);
          container.style.cursor = 'grab';
        }
      };

      const handleClick = (event: MouseEvent) => {
        const intersects = getIntersects(event);
        if (intersects.length > 0) {
          onSelectNode(intersects[0].object.userData);
        }
      };

      const handleResize = () => {
        if (!container || !renderer || !camera) return;
        const w = container.clientWidth;
        const h = container.clientHeight;
        camera.aspect = w / h;
        camera.updateProjectionMatrix();
        renderer.setSize(w, h);
      };

      container.addEventListener('mousemove', handleMouseMove);
      container.addEventListener('click', handleClick);
      window.addEventListener('resize', handleResize);

      const animate = () => {
        animId = requestAnimationFrame(animate);

        if (autoRotateRef.current) {
          scene.rotation.y += 0.002;
        }

        if (controls) {
          controls.update();
        }

        particlesGroup.children.forEach((p: any) => {
          p.userData.t += p.userData.speed;
          if (p.userData.t > 1) p.userData.t = 0;
          const pos = p.userData.curve.getPoint(p.userData.t);
          p.position.copy(pos);
        });

        renderer.render(scene, camera);
      };

      animate();

      return () => {
        cancelAnimationFrame(animId);
        container.removeEventListener('mousemove', handleMouseMove);
        container.removeEventListener('click', handleClick);
        window.removeEventListener('resize', handleResize);
        if (renderer) {
          renderer.dispose();
          if (container.contains(renderer.domElement)) {
            container.removeChild(renderer.domElement);
          }
        }
      };
    } catch (err) {
      console.warn('WebGL init error, falling back to 2D topology:', err);
      setWebGlAvailable(false);
    }
  }, [checkWebGL, onSelectNode]);

  const handleIsolateCayman = () => {
    setAutoRotate(false);
    if (cameraRef.current) {
      cameraRef.current.position.set(-45, 10, 80);
      cameraRef.current.lookAt(-35, -5, 35);
    }
    const caymanNode = FINANCIAL_NODES.find((n) => n.code === 'KY-GCM');
    if (caymanNode) onSelectNode(caymanNode);
  };

  const handleResetCamera = () => {
    setAutoRotate(true);
    if (cameraRef.current && sceneRef.current) {
      cameraRef.current.position.set(0, 30, 110);
      cameraRef.current.lookAt(0, 0, 0);
      sceneRef.current.rotation.y = 0;
    }
  };

  return (
    <div
      className="relative w-full rounded-xl overflow-hidden border border-[#DAD3C3] shadow-lg bg-[#1B1F2B]"
      role="region"
      aria-label="Interactive 3D Global Money Flow Topology Visualizer"
    >
      {webGlAvailable ? (
        <div ref={mountRef} className="w-full h-[480px] relative cursor-grab active:cursor-grabbing" tabIndex={0} />
      ) : (
        /* Accessible High-Performance 2D Topology Fallback */
        <div className="w-full h-[480px] p-6 flex flex-col justify-between bg-gradient-to-b from-[#1B1F2B] to-[#141720]">
          <div className="flex items-center justify-between text-xs font-mono text-slate-300">
            <span className="flex items-center gap-2 text-[#4C7A5E]">
              <span className="w-2 h-2 rounded-full bg-[#4C7A5E] animate-ping" />
              2D High-Res Topology Vector Mode
            </span>
            <span className="text-slate-400">Click any hub to audit node dossier</span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 my-auto">
            {FINANCIAL_NODES.map((node) => (
              <button
                key={node.code}
                onClick={() => onSelectNode(node)}
                className={`p-3 rounded-lg border text-left transition font-mono ${
                  selectedNode?.code === node.code
                    ? 'bg-[#3D5A80]/20 border-[#3D5A80] text-white shadow-md'
                    : 'bg-[#2B3040]/50 border-white/10 text-slate-200 hover:bg-[#2B3040]'
                }`}
              >
                <div className="flex items-center justify-between text-xs">
                  <span className="font-bold">{node.code}</span>
                  <span
                    className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                      node.type === 'high'
                        ? 'bg-[#C1443B]/20 text-[#C1443B]'
                        : node.type === 'med'
                        ? 'bg-[#C98A2E]/20 text-[#C98A2E]'
                        : 'bg-[#4C7A5E]/20 text-[#4C7A5E]'
                    }`}
                  >
                    Risk {node.risk}
                  </span>
                </div>
                <div className="text-xs text-white truncate mt-1">{node.name}</div>
                <div className="text-[10px] text-slate-400 mt-0.5">Vol: {node.dailyVolume}</div>
              </button>
            ))}
          </div>

          <div className="text-[11px] font-mono text-slate-400 text-center">
            SWIFT MT103 and Fedwire transfer topology active · 9 international nodes connected
          </div>
        </div>
      )}

      {/* Screen Reader Summary Table (WCAG 2.1 AA) */}
      <div className="sr-only">
        <table>
          <caption>Global Banking Node Risk Distribution</caption>
          <thead>
            <tr>
              <th>Node</th>
              <th>BIC</th>
              <th>Jurisdiction</th>
              <th>Risk Score</th>
              <th>Beneficial Ownership Status</th>
            </tr>
          </thead>
          <tbody>
            {FINANCIAL_NODES.map((n) => (
              <tr key={n.code}>
                <td>{n.name}</td>
                <td>{n.swiftBic}</td>
                <td>{n.city}</td>
                <td>{n.risk}</td>
                <td>{n.uboStatus}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* HUD Telemetry Overlay */}
      <div className="absolute top-4 left-4 p-3.5 rounded-lg bg-[#1B1F2B]/90 border border-[#2B3040] text-xs font-mono text-white pointer-events-none backdrop-blur shadow-md space-y-1 z-10">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-[#C1443B] animate-ping" />
          <span className="font-bold text-white">NEURAL NETWORK GRAPH ACTIVE</span>
        </div>
        <div className="text-[11px] text-slate-300">
          Nodes: {FINANCIAL_NODES.length} Global Corridors · Edges: {CONNECTIONS.length} SWIFT Wires
        </div>
        <div className="pt-1">
          {hoveredNode ? (
            <span
              className="font-bold"
              style={{
                color:
                  hoveredNode.type === 'high'
                    ? '#C1443B'
                    : hoveredNode.type === 'med'
                    ? '#C98A2E'
                    : '#4C7A5E',
              }}
            >
              AUDIT TARGET: {hoveredNode.name} ({hoveredNode.code}) · Risk: {hoveredNode.risk}
            </span>
          ) : (
            <span className="text-[#C98A2E] font-medium">Click or hover over any banking node to inspect...</span>
          )}
        </div>
      </div>

      {/* Floating Controls Toolbar */}
      <div className="absolute top-4 right-4 flex items-center gap-2 font-mono text-xs z-10">
        <button
          onClick={() => setAutoRotate(!autoRotate)}
          aria-label="Toggle 3D graph auto rotation"
          aria-pressed={autoRotate}
          className="px-3 py-1.5 rounded bg-[#ECE7DD] hover:bg-[#E2DDD1] border border-[#DAD3C3] text-[#22262E] font-medium transition flex items-center gap-1.5 shadow-sm"
        >
          <RotateCw className="w-3.5 h-3.5 text-[#3D5A80]" />
          <span>Auto-Rotate: {autoRotate ? 'ON' : 'OFF'}</span>
        </button>
        <button
          onClick={handleIsolateCayman}
          aria-label="Isolate Cayman high-risk anomaly corridor"
          className="px-3 py-1.5 rounded bg-[#C1443B]/15 hover:bg-[#C1443B]/25 border border-[#C1443B] text-[#C1443B] font-medium transition flex items-center gap-1.5 shadow-sm"
        >
          <AlertOctagon className="w-3.5 h-3.5" />
          <span>Isolate Cayman Threats</span>
        </button>
        <button
          onClick={handleResetCamera}
          aria-label="Reset 3D camera to default viewpoint"
          className="px-3 py-1.5 rounded bg-white hover:bg-slate-100 border border-[#DAD3C3] text-[#22262E] font-medium transition shadow-sm"
        >
          Reset View
        </button>
      </div>

      {/* Legend Overlay */}
      <div className="absolute bottom-4 right-4 p-2.5 rounded bg-[#1B1F2B]/90 border border-[#2B3040] text-[11px] font-mono text-slate-300 pointer-events-none backdrop-blur shadow-md flex items-center gap-4 z-10">
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#C1443B] inline-block" />
          <span>Critical Threat (Cayman / Panama)</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#C98A2E] inline-block" />
          <span>Structuring Surge</span>
        </div>
        <div className="flex items-center gap-1.5">
          <span className="w-2.5 h-2.5 rounded-full bg-[#4C7A5E] inline-block" />
          <span>Approved Clearing Hub</span>
        </div>
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────────────────────
// INTERACTIVE COMPLIANCE ANOMALY & RULE ENGINE SIMULATOR
// ─────────────────────────────────────────────────────────────
const RuleEngineSimulator: React.FC = () => {
  const [wireAmount, setWireAmount] = useState<number>(9480);
  const [ruleStructuring, setRuleStructuring] = useState<boolean>(true);
  const [ruleVelocity, setRuleVelocity] = useState<boolean>(true);
  const [ruleOffshore, setRuleOffshore] = useState<boolean>(true);
  const [ruleDormant, setRuleDormant] = useState<boolean>(false);

  // Compute AML Risk Score dynamically
  const calculatedRisk = useMemo(() => {
    let score = 15;
    if (wireAmount > 9000 && wireAmount < 10000) score += 32; // Smurfing proximity
    if (wireAmount >= 10000) score += 18;
    if (ruleStructuring) score += 24;
    if (ruleVelocity) score += 14;
    if (ruleOffshore) score += 20;
    if (ruleDormant) score += 12;
    return Math.min(score, 99);
  }, [wireAmount, ruleStructuring, ruleVelocity, ruleOffshore, ruleDormant]);

  const riskTier = calculatedRisk >= 80 ? 'CRITICAL ALERT' : calculatedRisk >= 50 ? 'MEDIUM SUSPICION' : 'APPROVED PASS';
  const riskColor = calculatedRisk >= 80 ? '#C1443B' : calculatedRisk >= 50 ? '#C98A2E' : '#4C7A5E';

  return (
    <div className="rounded-xl p-6 bg-white border border-[#DAD3C3] shadow-sm">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-4 border-b border-[#DAD3C3]">
        <div>
          <div className="flex items-center gap-2">
            <Sliders className="w-4 h-4 text-[#3D5A80]" />
            <h3 className="text-base font-bold text-[#22262E]">Live Rule Engine Simulator &amp; SHAP Calculator</h3>
          </div>
          <p className="text-xs text-[#6B6F7A]">
            Adjust transaction parameters to observe real-time risk scoring and explainable attribution.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span
            className="px-3 py-1 rounded font-mono text-xs font-bold"
            style={{ backgroundColor: `${riskColor}18`, color: riskColor, border: `1px solid ${riskColor}40` }}
          >
            {riskTier} · SCORE {calculatedRisk} / 100
          </span>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mt-6">
        {/* Controls */}
        <div className="space-y-4">
          <div>
            <div className="flex justify-between text-xs font-mono mb-1">
              <span className="text-[#6B6F7A]">Wire Amount ($ USD):</span>
              <span className="font-bold text-[#1B1F2B]">${wireAmount.toLocaleString()}</span>
            </div>
            <input
              type="range"
              min="1000"
              max="25000"
              step="100"
              value={wireAmount}
              onChange={(e) => setWireAmount(Number(e.target.value))}
              aria-label="Simulated wire amount slider"
              className="w-full accent-[#3D5A80] h-1.5 bg-[#DAD3C3] rounded cursor-pointer"
            />
            <div className="flex justify-between text-[10px] font-mono text-slate-400 mt-0.5">
              <span>$1,000 (Low)</span>
              <span className="text-[#C1443B] font-bold">$9,999 (BSA Threshold)</span>
              <span>$25,000 (CTR Mandatory)</span>
            </div>
          </div>

          <div className="space-y-2 pt-2">
            <span className="text-xs font-mono font-bold text-[#22262E] block">Active Rule Triggers:</span>

            <label className="flex items-center justify-between p-2 rounded bg-[#F8F6F0] border border-[#DAD3C3] text-xs font-mono cursor-pointer hover:bg-[#F2EFE8] transition">
              <span className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={ruleStructuring}
                  onChange={(e) => setRuleStructuring(e.target.checked)}
                  className="rounded text-[#3D5A80] focus:ring-0"
                />
                <span>R-STRUCT-04 (Sub-Threshold Smurfing)</span>
              </span>
              <span className="text-[#C1443B] font-bold">+24% SHAP</span>
            </label>

            <label className="flex items-center justify-between p-2 rounded bg-[#F8F6F0] border border-[#DAD3C3] text-xs font-mono cursor-pointer hover:bg-[#F2EFE8] transition">
              <span className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={ruleVelocity}
                  onChange={(e) => setRuleVelocity(e.target.checked)}
                  className="rounded text-[#3D5A80] focus:ring-0"
                />
                <span>R-VEL-02 (24h Velocity Spike Z &gt; 3.0)</span>
              </span>
              <span className="text-[#C98A2E] font-bold">+14% SHAP</span>
            </label>

            <label className="flex items-center justify-between p-2 rounded bg-[#F8F6F0] border border-[#DAD3C3] text-xs font-mono cursor-pointer hover:bg-[#F2EFE8] transition">
              <span className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={ruleOffshore}
                  onChange={(e) => setRuleOffshore(e.target.checked)}
                  className="rounded text-[#3D5A80] focus:ring-0"
                />
                <span>R-GEO-09 (High-Risk Secrecy Haven - KY/PA)</span>
              </span>
              <span className="text-[#C1443B] font-bold">+20% SHAP</span>
            </label>

            <label className="flex items-center justify-between p-2 rounded bg-[#F8F6F0] border border-[#DAD3C3] text-xs font-mono cursor-pointer hover:bg-[#F2EFE8] transition">
              <span className="flex items-center gap-2">
                <input
                  type="checkbox"
                  checked={ruleDormant}
                  onChange={(e) => setRuleDormant(e.target.checked)}
                  className="rounded text-[#3D5A80] focus:ring-0"
                />
                <span>R-DORM-01 (Sudden 180-Day Dormant Wakeup)</span>
              </span>
              <span className="text-[#C98A2E] font-bold">+12% SHAP</span>
            </label>
          </div>
        </div>

        {/* Explainable Output Waterfall */}
        <div className="p-4 rounded-lg bg-[#1B1F2B] text-white flex flex-col justify-between font-mono text-xs">
          <div>
            <div className="flex items-center justify-between pb-3 border-b border-[#2B3040]">
              <span className="text-slate-400">Model Inference Engine</span>
              <span className="text-[#4C7A5E] font-bold">XGBoost + TreeSHAP v2.4</span>
            </div>

            <div className="space-y-3 mt-4">
              <div>
                <div className="flex justify-between text-[11px] mb-1">
                  <span className="text-slate-300">Composite Risk Confidence</span>
                  <span style={{ color: riskColor }} className="font-bold">
                    {calculatedRisk}%
                  </span>
                </div>
                <div className="w-full bg-[#2B3040] h-2 rounded-full overflow-hidden">
                  <div
                    className="h-full transition-all duration-300 rounded-full"
                    style={{ width: `${calculatedRisk}%`, backgroundColor: riskColor }}
                  />
                </div>
              </div>

              <div className="pt-2 text-[11px] text-slate-300 space-y-1">
                <div>
                  <strong>Recommended MLRO Action:</strong>
                </div>
                {calculatedRisk >= 80 ? (
                  <div className="text-[#C1443B]">
                    ⚠ Block SWIFT release immediately. Generate FinCEN SAR XML filing package for review.
                  </div>
                ) : calculatedRisk >= 50 ? (
                  <div className="text-[#C98A2E]">
                    ⚡ Route to L2 Investigator for Enhanced Due Diligence (EDD) source-of-wealth inquiry.
                  </div>
                ) : (
                  <div className="text-[#4C7A5E]">
                    ✓ Within statistical baseline parameters. Instant clearing clearance granted.
                  </div>
                )}
              </div>
            </div>
          </div>

          <div className="pt-4 border-t border-[#2B3040] flex items-center justify-between text-[10px] text-slate-400">
            <span>Inference Latency: &lt; 28ms</span>
            <a href="/dashboard" className="text-[#8BB9E0] hover:underline flex items-center gap-1">
              <span>Inspect in Cockpit</span>
              <ArrowRight className="w-3 h-3" />
            </a>
          </div>
        </div>
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────────────────────
// INTERACTIVE KYC / SANCTIONS FUZZY MATCH TESTER
// ─────────────────────────────────────────────────────────────
const SanctionsRadarTester: React.FC = () => {
  const [searchTerm, setSearchTerm] = useState('Smirnow');
  const [threshold, setThreshold] = useState(85);

  const testDatabase = [
    { name: 'Wladimir Smirnow', list: 'OFAC SDN Blocklist', type: 'Designated Individual', country: 'RU', rawScore: 94 },
    { name: 'Tobias M. Varga', list: 'EU Consolidated Sanctions', type: 'Special Scrutiny PEP', country: 'HU', rawScore: 89 },
    { name: 'Alexander Petrov', list: 'UK OFSI Sanctions', type: 'Asset Freeze Target', country: 'RU', rawScore: 78 },
    { name: 'Maria Santos Chen', list: 'Interpol Red Notice', type: 'Transnational Narcotics', country: 'MX', rawScore: 84 },
    { name: 'General Ahmed Al-Hassan', list: 'UN Security Council 1267', type: 'Terror Financing Watch', country: 'SD', rawScore: 92 },
  ];

  const matchedResults = useMemo(() => {
    if (!searchTerm.trim()) return [];
    return testDatabase.filter((item) => {
      const isNameMatch = item.name.toLowerCase().includes(searchTerm.toLowerCase());
      return isNameMatch && item.rawScore >= threshold;
    });
  }, [searchTerm, threshold]);

  return (
    <div className="rounded-xl p-6 bg-white border border-[#DAD3C3] shadow-sm flex flex-col justify-between">
      <div>
        <div className="w-10 h-10 rounded bg-[#C98A2E]/10 border border-[#C98A2E]/30 text-[#C98A2E] flex items-center justify-center mb-3">
          <ScanFace className="w-5 h-5" />
        </div>
        <h3 className="text-xl font-bold text-[#22262E]">Phonetic KYC / KYB Radar</h3>
        <p className="text-sm text-[#6B6F7A] mt-1 leading-relaxed">
          Test real-time Jaro-Winkler phonetic fuzzy matching across OFAC SDN, EU, and PEP watchlists.
        </p>
      </div>

      <div className="mt-6 pt-4 border-t border-[#DAD3C3] space-y-3">
        <div className="relative">
          <Search className="w-4 h-4 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Type name to test (e.g. Smirnow, Varga, Al-Hassan)..."
            aria-label="Search sanctions test radar"
            className="w-full pl-9 pr-3 py-1.5 rounded border border-[#DAD3C3] bg-[#F8F6F0] text-xs font-mono text-[#22262E] focus:outline-none focus:border-[#3D5A80]"
          />
        </div>

        <div className="space-y-1">
          <div className="flex justify-between text-xs font-mono">
            <span className="text-[#6B6F7A]">Fuzzy Sensitivity Limit:</span>
            <span className="text-[#C98A2E] font-bold">{threshold}% Match Threshold</span>
          </div>
          <input
            type="range"
            min="70"
            max="95"
            value={threshold}
            onChange={(e) => setThreshold(Number(e.target.value))}
            aria-label="Fuzzy sensitivity threshold"
            className="w-full accent-[#C98A2E] h-1.5 bg-[#DAD3C3] rounded cursor-pointer"
          />
        </div>

        <div className="min-h-[72px] space-y-1.5">
          {matchedResults.length > 0 ? (
            matchedResults.map((hit) => (
              <div key={hit.name} className="p-2 rounded bg-[#C1443B]/10 border border-[#C1443B]/30 text-xs font-mono">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-[#1B1F2B]">{hit.name}</span>
                  <span className="text-[#C1443B] font-bold">MATCH {hit.rawScore}%</span>
                </div>
                <div className="text-[10px] text-[#6B6F7A] mt-0.5">
                  {hit.list} · {hit.type} ({hit.country})
                </div>
              </div>
            ))
          ) : (
            <div className="p-2 rounded bg-[#4C7A5E]/10 border border-[#4C7A5E]/30 text-xs font-mono text-[#4C7A5E] flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>No watchlist sanction match above {threshold}% sensitivity limit.</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

// ─────────────────────────────────────────────────────────────
// MAIN AML LANDING PAGE COMPONENT
// ─────────────────────────────────────────────────────────────
export const AmlLandingPage: React.FC = () => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);
  const [videoModalOpen, setVideoModalOpen] = useState(false);
  const [isPlayingDemo, setIsPlayingDemo] = useState(true);
  const [selectedNode, setSelectedNode] = useState<FinancialNode | null>(null);

  // Keyboard navigation & modal accessibility
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && videoModalOpen) {
        setVideoModalOpen(false);
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [videoModalOpen]);

  return (
    <div className="min-h-screen bg-[#ECE7DD] text-[#22262E] font-sans selection:bg-[#3D5A80] selection:text-white relative overflow-x-hidden">
      
      {/* ── SUBTLE PAPER TEXTURE BACKGROUND GRID ── */}
      <div
        className="fixed inset-0 pointer-events-none z-0 opacity-60"
        style={{
          backgroundImage: 'radial-gradient(rgba(34, 38, 46, 0.08) 1px, transparent 1px)',
          backgroundSize: '28px 28px',
        }}
      />

      {/* ═══════════════════════════════════════════════════════════
           1. CHARCOAL-NAVY STICKY HEADER (#1B1F2B)
      ════════════════════════════════════════════════════════════ */}
      <header className="sticky top-0 z-40 w-full backdrop-blur-md bg-[#1B1F2B]/95 border-b border-[#2B3040] shadow-sm">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-18 flex items-center justify-between">
          
          {/* Logo Section */}
          <a href="/" className="flex items-center gap-3.5 group focus:outline-none p-1 rounded">
            <div className="relative w-9 h-9 rounded-lg bg-[#2B3040] border border-[#3D5A80]/40 flex items-center justify-center text-white shadow-sm group-hover:border-[#3D5A80] transition">
              <Shield className="w-5 h-5 text-[#4C7A5E]" />
            </div>

            <div>
              <div className="flex items-center gap-2">
                <span className="text-lg font-bold tracking-tight text-white">SENTINEL</span>
                <span className="text-[10px] font-mono uppercase px-1.5 py-0.5 rounded bg-[#3D5A80]/20 text-[#8BB9E0] border border-[#3D5A80]/30 font-semibold">
                  AML v4.2
                </span>
              </div>
              <span className="text-[10px] font-mono tracking-wider text-slate-400 uppercase block -mt-0.5">
                Institutional Defense Core
              </span>
            </div>
          </a>

          {/* Desktop Nav Links */}
          <nav className="hidden md:flex items-center gap-1 lg:gap-2 text-xs font-mono" aria-label="Main Navigation">
            <a href="#cockpit-preview" className="px-3.5 py-2 text-slate-300 hover:text-white rounded hover:bg-white/5 transition">
              Cockpit Showcase
            </a>
            <a href="#threejs-section" className="px-3.5 py-2 text-slate-300 hover:text-white rounded hover:bg-white/5 transition">
              3D Flow Matrix
            </a>
            <a href="#simulator" className="px-3.5 py-2 text-slate-300 hover:text-white rounded hover:bg-white/5 transition">
              Rule Simulator
            </a>
            <a href="#features" className="px-3.5 py-2 text-slate-300 hover:text-white rounded hover:bg-white/5 transition">
              Compliance Modules
            </a>
            <a href="#architecture" className="px-3.5 py-2 text-slate-300 hover:text-white rounded hover:bg-white/5 transition">
              Architecture
            </a>
            <a href="#pricing" className="px-3.5 py-2 text-slate-300 hover:text-white rounded hover:bg-white/5 transition">
              Sovereign MSA
            </a>
          </nav>

          {/* Quick Action Buttons */}
          <div className="hidden sm:flex items-center gap-3">
            <a
              href="/login"
              className="px-3.5 py-2 text-xs font-mono font-medium text-slate-200 hover:text-white hover:bg-white/10 rounded transition"
            >
              Analyst Login
            </a>
            <a
              href="/dashboard"
              className="inline-flex items-center gap-2 px-4 py-2 rounded text-xs font-mono font-semibold text-white bg-[#3D5A80] hover:bg-[#4A6D99] shadow-sm transition active:scale-[0.98]"
            >
              <span>Launch Case Cockpit</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </a>
          </div>

          {/* Mobile Menu Button */}
          <button
            onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
            aria-label="Toggle navigation menu"
            aria-expanded={mobileMenuOpen}
            className="md:hidden p-2 rounded text-slate-300 hover:text-white hover:bg-white/5 focus:outline-none"
          >
            <Menu className="w-6 h-6" />
          </button>
        </div>

        {/* Mobile Navigation Drawer */}
        <AnimatePresence>
          {mobileMenuOpen && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 'auto', opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="md:hidden bg-[#1B1F2B] border-b border-[#2B3040] px-4 py-4 space-y-2 text-xs font-mono"
            >
              <a href="#cockpit-preview" className="block py-1.5 text-slate-300" onClick={() => setMobileMenuOpen(false)}>
                Cockpit Showcase
              </a>
              <a href="#threejs-section" className="block py-1.5 text-slate-300" onClick={() => setMobileMenuOpen(false)}>
                3D Flow Matrix
              </a>
              <a href="#simulator" className="block py-1.5 text-slate-300" onClick={() => setMobileMenuOpen(false)}>
                Rule Simulator
              </a>
              <a href="#features" className="block py-1.5 text-slate-300" onClick={() => setMobileMenuOpen(false)}>
                Compliance Modules
              </a>
              <a href="#architecture" className="block py-1.5 text-slate-300" onClick={() => setMobileMenuOpen(false)}>
                Architecture
              </a>
              <a href="#pricing" className="block py-1.5 text-slate-300" onClick={() => setMobileMenuOpen(false)}>
                Pricing &amp; Licensing
              </a>
              <div className="pt-2 border-t border-[#2B3040] flex flex-col gap-2">
                <a href="/login" className="py-2 text-center text-slate-200 bg-white/5 rounded">
                  Analyst Login
                </a>
                <a href="/dashboard" className="py-2 text-center text-white bg-[#3D5A80] rounded font-bold">
                  Launch Case Cockpit
                </a>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </header>


      {/* ═══════════════════════════════════════════════════════════
           2. HERO SECTION (WARM PAPER CANVOAS #ECE7DD)
      ════════════════════════════════════════════════════════════ */}
      <section className="relative z-10 pt-12 sm:pt-16 pb-16 overflow-hidden">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          
          {/* Regulatory Pill Badge */}
          <div className="flex justify-center mb-5">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-white border border-[#DAD3C3] text-xs font-mono text-[#22262E] shadow-sm">
              <span className="w-2 h-2 rounded-full bg-[#4C7A5E] animate-ping" />
              <span className="font-semibold text-[#1B1F2B]">Cognitive Compliance Engine v4.2.1</span>
              <span className="text-[#8F93A0]">|</span>
              <span className="text-[#6B6F7A]">FinCEN BSA &amp; FATF Standards</span>
            </div>
          </div>

          {/* Hero Headline & Sub-headline */}
          <div className="text-center max-w-4xl mx-auto space-y-4">
            <h1 className="text-3xl sm:text-5xl lg:text-6xl font-bold tracking-tight text-[#22262E] leading-tight font-sans">
              Institutional Defense Against <br className="hidden sm:inline" />
              <span className="text-[#3D5A80]">Complex Financial Crime</span>
            </h1>
            
            <p className="text-sm sm:text-lg text-[#6B6F7A] max-w-2xl mx-auto font-normal leading-relaxed">
              Sub-second transaction monitoring, multi-hop UBO graph traversal, and automated FinCEN regulatory filings. Built strictly for Tier-1 banks, sovereign treasuries, and regulated fintechs.
            </p>

            {/* CTAs */}
            <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-3">
              <a
                href="/dashboard"
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg text-sm font-semibold text-white bg-[#1B1F2B] hover:bg-[#2B3040] shadow-md transition"
              >
                <Shield className="w-4 h-4 text-[#4C7A5E]" />
                <span>Launch Case Cockpit</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </a>

              <button
                onClick={() => setVideoModalOpen(true)}
                aria-label="Open case investigation video walkthrough modal"
                className="w-full sm:w-auto inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg text-sm font-semibold text-[#1B1F2B] bg-white hover:bg-[#F9F8F5] border border-[#DAD3C3] shadow-sm transition"
              >
                <PlayCircle className="w-4 h-4 text-[#C98A2E]" />
                <span>Watch Cockpit Video Tour (1:45)</span>
              </button>
            </div>

            {/* Metric KPI Cards */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 pt-8 max-w-3xl mx-auto font-mono">
              <div className="p-3 rounded-lg bg-white border border-[#DAD3C3] shadow-sm text-center">
                <div className="text-xl sm:text-2xl font-bold text-[#1B1F2B]">99.4%</div>
                <div className="text-[10px] uppercase tracking-wider text-[#6B6F7A] mt-0.5">False Positive Drop</div>
              </div>
              <div className="p-3 rounded-lg bg-white border border-[#DAD3C3] shadow-sm text-center">
                <div className="text-xl sm:text-2xl font-bold text-[#3D5A80]">&lt; 42ms</div>
                <div className="text-[10px] uppercase tracking-wider text-[#6B6F7A] mt-0.5">Inference Latency</div>
              </div>
              <div className="p-3 rounded-lg bg-white border border-[#DAD3C3] shadow-sm text-center">
                <div className="text-xl sm:text-2xl font-bold text-[#1B1F2B]">$48.5B+</div>
                <div className="text-[10px] uppercase tracking-wider text-[#6B6F7A] mt-0.5">Volume Screened</div>
              </div>
              <div className="p-3 rounded-lg bg-white border border-[#DAD3C3] shadow-sm text-center">
                <div className="text-xl sm:text-2xl font-bold text-[#4C7A5E]">100%</div>
                <div className="text-[10px] uppercase tracking-wider text-[#6B6F7A] mt-0.5">FinCEN Acceptance</div>
              </div>
            </div>
          </div>

          {/* ── HERO SHOWCASE: VISIBLE COCKPIT PHOTOGRAPH & VIDEO DEMO ── */}
          <div id="cockpit-preview" className="mt-12 max-w-5xl mx-auto">
            <div className="rounded-xl overflow-hidden border-2 border-[#DAD3C3] shadow-xl relative bg-white">
              
              {/* Cockpit Window Top Bar */}
              <div className="h-10 px-4 bg-[#1B1F2B] border-b border-[#2B3040] flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <span className="w-2.5 h-2.5 rounded-full bg-[#C1443B] inline-block" />
                  <span className="w-2.5 h-2.5 rounded-full bg-[#C98A2E] inline-block" />
                  <span className="w-2.5 h-2.5 rounded-full bg-[#4C7A5E] inline-block" />
                  <span className="text-xs font-mono text-slate-300 ml-2 hidden sm:inline">
                    case-investigation-cockpit // case-aml-2026-04471
                  </span>
                </div>
                
                <div className="flex items-center gap-2">
                  <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded bg-[#4C7A5E]/20 text-[#4C7A5E] text-[10px] font-mono font-bold">
                    ● LIVE POSTGRES TELEMETRY
                  </span>
                  <a href="/dashboard" className="text-xs font-mono text-slate-200 hover:text-white bg-white/10 px-2 py-0.5 rounded flex items-center gap-1">
                    Open Full System →
                  </a>
                </div>
              </div>

              {/* The Real Cockpit Visual Photograph */}
              <div className="relative aspect-[16/9] w-full bg-[#ECE7DD] overflow-hidden group">
                <img
                  src="/static/images/aml_warm_cockpit.jpg"
                  alt="Sentinel AML 3-Pane Investigation Cockpit Interface showing case queue, customer 360, and evidence timeline"
                  decoding="async"
                  className="w-full h-full object-cover object-top transition duration-500 group-hover:scale-[1.01]"
                />

                {/* Video Play Overlay Banner */}
                <div className="absolute inset-0 bg-gradient-to-t from-[#1B1F2B]/85 via-transparent to-transparent flex flex-col justify-end p-6 sm:p-8">
                  <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
                    <div className="text-white space-y-1">
                      <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded bg-[#C1443B] text-white text-xs font-mono font-bold">
                        CRITICAL ALERT · RISK 92 / 100
                      </div>
                      <h3 className="text-lg sm:text-xl font-bold">
                        Tobias M. Varga — $9,480.00 SWIFT Wire Structuring
                      </h3>
                      <p className="text-xs text-slate-300 font-mono">
                        Offshore entity Harlow Kane Ltd · 🇰🇾 Cayman Islands · Trigger: R-STRUCT-04
                      </p>
                    </div>

                    <button
                      onClick={() => setVideoModalOpen(true)}
                      aria-label="Play live video tour of case cockpit"
                      className="inline-flex items-center gap-2 px-5 py-2.5 rounded-lg text-xs font-bold font-mono text-[#1B1F2B] bg-white hover:bg-[#ECE7DD] shadow-lg transition"
                    >
                      <Play className="w-4 h-4 fill-current text-[#C1443B]" />
                      <span>PLAY LIVE VIDEO TOUR</span>
                    </button>
                  </div>
                </div>
              </div>

              {/* Bottom Telemetry Breadcrumbs */}
              <div className="h-10 px-4 bg-[#F5F2EB] border-t border-[#DAD3C3] flex items-center justify-between text-xs font-mono text-[#6B6F7A]">
                <div className="flex items-center gap-4">
                  <span><strong>Queue:</strong> Case 1 of 6</span>
                  <span className="hidden sm:inline"><strong>Rules Active:</strong> 41 engines</span>
                  <span className="hidden sm:inline"><strong>Status:</strong> Awaiting Compliance Signoff</span>
                </div>
                <div className="text-[#3D5A80] font-semibold">
                  Hotkeys: <kbd className="px-1 py-0.5 bg-white border border-[#DAD3C3] rounded">A</kbd> Approve <kbd className="px-1 py-0.5 bg-white border border-[#DAD3C3] rounded">B</kbd> Block <kbd className="px-1 py-0.5 bg-white border border-[#DAD3C3] rounded">→</kbd> Next
                </div>
              </div>

            </div>
          </div>

        </div>
      </section>


      {/* ═══════════════════════════════════════════════════════════
           3. THREE.JS INTERACTIVE 3D FINANCIAL NETWORK GRAPH
      ════════════════════════════════════════════════════════════ */}
      <section id="threejs-section" className="relative z-10 py-16 border-t border-[#DAD3C3] bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          
          <div className="flex flex-col md:flex-row items-start md:items-end justify-between gap-4 mb-8">
            <div>
              <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded bg-[#3D5A80]/10 text-[#3D5A80] text-xs font-mono font-bold mb-2">
                <Network className="w-3.5 h-3.5" />
                THREE.JS INTERACTIVE VISUALIZATION
              </div>
              <h2 className="text-2xl sm:text-3xl font-bold text-[#22262E]">
                3D Global Money Flow Topology &amp; Anomaly Corridors
              </h2>
              <p className="text-sm text-[#6B6F7A] mt-1">
                Rotate, zoom, and inspect real-time international fund movements between banking nodes and offshore secrecy endpoints.
              </p>
            </div>
            {selectedNode && (
              <button
                onClick={() => setSelectedNode(null)}
                className="text-xs font-mono text-[#3D5A80] hover:underline flex items-center gap-1"
              >
                Clear Node Selection ({selectedNode.code})
              </button>
            )}
          </div>

          {/* Three.js Interactive Component */}
          <ThreeJsMoneyFlowGraph onSelectNode={setSelectedNode} selectedNode={selectedNode} />

          {/* Selected Node Detailed Audit Inspector Drawer */}
          <AnimatePresence>
            {selectedNode && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: 10 }}
                className="mt-4 p-4 rounded-xl bg-[#F8F6F0] border border-[#DAD3C3] font-mono text-xs shadow-md"
              >
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-[#DAD3C3]">
                  <div className="flex items-center gap-2">
                    <span
                      className={`w-3 h-3 rounded-full ${
                        selectedNode.type === 'high'
                          ? 'bg-[#C1443B]'
                          : selectedNode.type === 'med'
                          ? 'bg-[#C98A2E]'
                          : 'bg-[#4C7A5E]'
                      }`}
                    />
                    <strong className="text-sm text-[#1B1F2B]">{selectedNode.name} ({selectedNode.code})</strong>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="px-2 py-0.5 rounded bg-[#1B1F2B] text-white font-bold">
                      BIC: {selectedNode.swiftBic}
                    </span>
                    <span className="px-2 py-0.5 rounded bg-[#C1443B]/10 text-[#C1443B] font-bold border border-[#C1443B]/30">
                      RISK SCORE {selectedNode.risk}
                    </span>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-3 text-[11px]">
                  <div>
                    <span className="text-[#6B6F7A] block">Beneficial Ownership (UBO):</span>
                    <span className="text-[#1B1F2B] font-semibold">{selectedNode.uboStatus}</span>
                  </div>
                  <div>
                    <span className="text-[#6B6F7A] block">24h Correlated Clearing Volume:</span>
                    <span className="text-[#1B1F2B] font-semibold">{selectedNode.dailyVolume} USD</span>
                  </div>
                  <div className="flex sm:justify-end items-center">
                    <a
                      href={`/customers/${selectedNode.code}`}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded bg-[#3D5A80] text-white font-semibold hover:bg-[#4A6D99] transition"
                    >
                      <span>Open Customer 360 Dossier</span>
                      <ArrowRight className="w-3.5 h-3.5" />
                    </a>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>

        </div>
      </section>


      {/* ═══════════════════════════════════════════════════════════
           4. LIVE RULE ENGINE & SHAP EXPLAINABILITY SIMULATOR
      ════════════════════════════════════════════════════════════ */}
      <section id="simulator" className="relative z-10 py-16 border-t border-[#DAD3C3] bg-[#ECE7DD]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="text-center max-w-3xl mx-auto mb-10 space-y-2">
            <div className="inline-flex items-center gap-2 px-3 py-0.5 rounded-full bg-white border border-[#DAD3C3] text-xs font-mono text-[#3D5A80] uppercase tracking-wider font-semibold">
              Interactive Compliance Sandbox
            </div>
            <h2 className="text-3xl sm:text-4xl font-bold text-[#22262E]">
              Test The Real-Time Scoring Algorithm
            </h2>
            <p className="text-sm text-[#6B6F7A]">
              Simulate high-velocity wire structuring and observe mathematical SHAP feature attribution in real time.
            </p>
          </div>

          <RuleEngineSimulator />
        </div>
      </section>


      {/* ═══════════════════════════════════════════════════════════
           5. INTERACTIVE COMPLIANCE MODULES (BENTO GRID IN #FFFFFF)
      ════════════════════════════════════════════════════════════ */}
      <section id="features" className="relative z-10 py-16 border-t border-[#DAD3C3] bg-[#ECE7DD]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          
          <div className="text-center max-w-3xl mx-auto mb-12 space-y-2">
            <div className="inline-flex items-center gap-2 px-3 py-0.5 rounded-full bg-white border border-[#DAD3C3] text-xs font-mono text-[#3D5A80] uppercase tracking-wider font-semibold">
              Architected for Tier-1 Financial Institutions
            </div>
            <h2 className="text-3xl sm:text-4xl font-bold text-[#22262E]">
              Enterprise Compliance Modules Built for Zero Error
            </h2>
            <p className="text-sm sm:text-base text-[#6B6F7A]">
              Replace legacy rule bottlenecks with real-time stream ingestion, multi-hop UBO topology, and explainable AI models.
            </p>
          </div>

          {/* Bento Grid */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">

            {/* Card 1: Real-Time Stream Scoring */}
            <div className="md:col-span-2 rounded-xl p-6 bg-white border border-[#DAD3C3] shadow-sm flex flex-col justify-between hover:border-[#3D5A80] transition">
              <div className="flex items-start justify-between">
                <div className="space-y-2 max-w-md">
                  <div className="w-10 h-10 rounded bg-[#3D5A80]/10 border border-[#3D5A80]/30 text-[#3D5A80] flex items-center justify-center">
                    <Activity className="w-5 h-5" />
                  </div>
                  <h3 className="text-xl font-bold text-[#22262E]">Real-Time Transaction Stream Scoring</h3>
                  <p className="text-sm text-[#6B6F7A] leading-relaxed">
                    Stream ingestion evaluating thousands of SWIFT MT103, Fedwire, and ACH transfers with deterministic sub-50ms rule triggers and behavioral baseline deviation.
                  </p>
                </div>
                <span className="px-2 py-1 rounded bg-[#3D5A80]/10 text-[#3D5A80] border border-[#3D5A80]/30 text-xs font-mono font-bold">
                  120,000 TX/SEC
                </span>
              </div>

              {/* Ingestion Stream Mock */}
              <div className="mt-6 pt-4 border-t border-[#DAD3C3]">
                <div className="text-xs font-mono font-bold text-[#22262E] mb-2">Live Ingestion Telemetry Stream</div>
                <div className="space-y-1.5 font-mono text-xs">
                  <div className="p-2 rounded bg-[#F8F6F0] border border-[#DAD3C3] flex items-center justify-between">
                    <span className="text-[#1B1F2B] font-semibold">SWIFT // Tobias M. Varga</span>
                    <span className="text-[#6B6F7A]">→ Harlow Kane Ltd (KY)</span>
                    <span className="font-bold text-[#1B1F2B]">$9,480.00</span>
                    <span className="px-2 py-0.5 rounded bg-[#C1443B]/10 text-[#C1443B] border border-[#C1443B]/30 font-bold">
                      92% CTR TRIGGER
                    </span>
                  </div>
                  <div className="p-2 rounded bg-[#F8F6F0] border border-[#DAD3C3] flex items-center justify-between">
                    <span className="text-[#1B1F2B] font-semibold">FEDWIRE // Renata Varga</span>
                    <span className="text-[#6B6F7A]">→ Panama Maritime S.A.</span>
                    <span className="font-bold text-[#1B1F2B]">$14,200.00</span>
                    <span className="px-2 py-0.5 rounded bg-[#C1443B]/10 text-[#C1443B] border border-[#C1443B]/30 font-bold">
                      88% SHELL HIT
                    </span>
                  </div>
                  <div className="p-2 rounded bg-[#F8F6F0] border border-[#DAD3C3] flex items-center justify-between">
                    <span className="text-[#1B1F2B] font-semibold">ACH // Pacific Trust</span>
                    <span className="text-[#6B6F7A]">→ Munich Spare Parts (DE)</span>
                    <span className="font-bold text-[#1B1F2B]">$3,100.00</span>
                    <span className="px-2 py-0.5 rounded bg-[#4C7A5E]/10 text-[#4C7A5E] border border-[#4C7A5E]/30 font-bold">
                      28% CLEARED
                    </span>
                  </div>
                </div>
              </div>
            </div>

            {/* Card 2: Interactive Phonetic KYC / KYB */}
            <SanctionsRadarTester />

            {/* Card 3: Graph Intelligence & UBO */}
            <div className="rounded-xl p-6 bg-white border border-[#DAD3C3] shadow-sm flex flex-col justify-between hover:border-[#3D5A80] transition">
              <div>
                <div className="w-10 h-10 rounded bg-[#3D5A80]/10 border border-[#3D5A80]/30 text-[#3D5A80] flex items-center justify-center mb-3">
                  <Network className="w-5 h-5" />
                </div>
                <h3 className="text-xl font-bold text-[#22262E]">Neo4j Graph Topology &amp; UBO</h3>
                <p className="text-sm text-[#6B6F7A] mt-1 leading-relaxed">
                  Autonomous 2-hop graph traversals uncover Ultimate Beneficial Owners (UBO), circular smurfing syndicates, and offshore secrecy networks.
                </p>
              </div>

              <div className="mt-6 pt-4 border-t border-[#DAD3C3] flex items-center justify-around py-2">
                <div className="text-center">
                  <div className="w-8 h-8 rounded-full bg-[#3D5A80] text-white flex items-center justify-center text-xs font-mono font-bold mx-auto">TV</div>
                  <span className="text-[10px] font-mono text-[#6B6F7A] block mt-1">Sender</span>
                </div>
                <div className="text-[#6B6F7A] font-mono text-xs">→</div>
                <div className="text-center">
                  <div className="w-10 h-10 rounded-full bg-[#C1443B] text-white flex items-center justify-center text-xs font-mono font-bold mx-auto animate-pulse">UBO</div>
                  <span className="text-[10px] font-mono text-[#C1443B] block mt-1 font-bold">60% Offshore</span>
                </div>
                <div className="text-[#6B6F7A] font-mono text-xs">→</div>
                <div className="text-center">
                  <div className="w-8 h-8 rounded-full bg-[#4C7A5E] text-white flex items-center justify-center text-xs font-mono font-bold mx-auto">HK</div>
                  <span className="text-[10px] font-mono text-[#6B6F7A] block mt-1">Cayman Ltd</span>
                </div>
              </div>
            </div>

            {/* Card 4: Explainable AI (SHAP) */}
            <div className="rounded-xl p-6 bg-white border border-[#DAD3C3] shadow-sm flex flex-col justify-between hover:border-[#3D5A80] transition">
              <div>
                <div className="w-10 h-10 rounded bg-[#1B1F2B]/10 border border-[#1B1F2B]/20 text-[#1B1F2B] flex items-center justify-center mb-3">
                  <PieChart className="w-5 h-5" />
                </div>
                <h3 className="text-xl font-bold text-[#22262E]">Explainable AI (SHAP)</h3>
                <p className="text-sm text-[#6B6F7A] mt-1 leading-relaxed">
                  No black-box risk. Every flagged transaction delivers mathematically provable SHAP risk attribution waterfalls.
                </p>
              </div>

              <div className="mt-6 pt-4 border-t border-[#DAD3C3] space-y-2 font-mono text-xs">
                <div className="flex justify-between">
                  <span className="text-[#6B6F7A]">CTR Threshold Proximity</span>
                  <span className="text-[#C1443B] font-bold">+48%</span>
                </div>
                <div className="w-full bg-[#E5DFD3] h-1.5 rounded overflow-hidden">
                  <div className="bg-[#C1443B] h-full w-[48%]" />
                </div>
                <div className="flex justify-between pt-1">
                  <span className="text-[#6B6F7A]">High-Risk Jurisdiction</span>
                  <span className="text-[#C1443B] font-bold">+32%</span>
                </div>
                <div className="w-full bg-[#E5DFD3] h-1.5 rounded overflow-hidden">
                  <div className="bg-[#C1443B] h-full w-[32%]" />
                </div>
              </div>
            </div>

            {/* Card 5: FinCEN Regulatory SAR Batches */}
            <div className="rounded-xl p-6 bg-white border border-[#DAD3C3] shadow-sm flex flex-col justify-between hover:border-[#3D5A80] transition">
              <div>
                <div className="w-10 h-10 rounded bg-[#4C7A5E]/10 border border-[#4C7A5E]/30 text-[#4C7A5E] flex items-center justify-center mb-3">
                  <Archive className="w-5 h-5" />
                </div>
                <h3 className="text-xl font-bold text-[#22262E]">1-Click FinCEN SAR Batches</h3>
                <p className="text-sm text-[#6B6F7A] mt-1 leading-relaxed">
                  Automated aggregation of suspicious cases into sealed XML batch containers with cryptographic SHA-256 seals.
                </p>
              </div>

              <div className="mt-6 pt-4 border-t border-[#DAD3C3] flex items-center justify-between font-mono text-xs">
                <div>
                  <span className="text-[#4C7A5E] font-bold">✓ BSA XML Validated</span>
                  <div className="text-[10px] text-[#6B6F7A]">SHA-256 Sealed</div>
                </div>
                <a href="/dashboard" className="px-3 py-1 bg-[#1B1F2B] text-white rounded text-xs hover:bg-[#2B3040] transition">
                  Preview Batch →
                </a>
              </div>
            </div>

            {/* Card 6: Sovereign Cryptographic Security */}
            <div className="md:col-span-3 rounded-xl p-6 sm:p-8 bg-white border border-[#DAD3C3] shadow-sm">
              <div className="grid grid-cols-1 md:grid-cols-4 gap-6 items-center">
                <div className="md:col-span-2 space-y-2">
                  <div className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded bg-[#4C7A5E]/10 border border-[#4C7A5E]/30 text-[#4C7A5E] text-xs font-mono font-bold">
                    <Lock className="w-3.5 h-3.5" />
                    SOVEREIGN SECURITY COMPLIANCE
                  </div>
                  <h3 className="text-2xl font-bold text-[#22262E]">Zero-Trust Cryptographic Architecture</h3>
                  <p className="text-sm text-[#6B6F7A] leading-relaxed">
                    Argon2id password hashing, asymmetric RS256 token rotation with RFC 7517 JWKS endpoints, PostgreSQL Row-Level Security, and strict anti-CSRF token verification.
                  </p>
                </div>

                <div className="md:col-span-2 grid grid-cols-2 gap-3 font-mono text-xs">
                  <div className="p-3 rounded bg-[#F8F6F0] border border-[#DAD3C3] flex items-center gap-2.5">
                    <Key className="w-4 h-4 text-[#3D5A80]" />
                    <div>
                      <div className="font-bold text-[#1B1F2B]">RS256 &amp; JWKS</div>
                      <div className="text-[10px] text-[#6B6F7A]">RFC 7517 public keys</div>
                    </div>
                  </div>
                  <div className="p-3 rounded bg-[#F8F6F0] border border-[#DAD3C3] flex items-center gap-2.5">
                    <Shield className="w-4 h-4 text-[#4C7A5E]" />
                    <div>
                      <div className="font-bold text-[#1B1F2B]">PostgreSQL RLS</div>
                      <div className="text-[10px] text-[#6B6F7A]">Tenant data isolation</div>
                    </div>
                  </div>
                  <div className="p-3 rounded bg-[#F8F6F0] border border-[#DAD3C3] flex items-center gap-2.5">
                    <Database className="w-4 h-4 text-[#C98A2E]" />
                    <div>
                      <div className="font-bold text-[#1B1F2B]">Argon2id Hash</div>
                      <div className="text-[10px] text-[#6B6F7A]">Transparent rehash</div>
                    </div>
                  </div>
                  <div className="p-3 rounded bg-[#F8F6F0] border border-[#DAD3C3] flex items-center gap-2.5">
                    <Server className="w-4 h-4 text-[#1B1F2B]" />
                    <div>
                      <div className="font-bold text-[#1B1F2B]">Anti-CSRF Guard</div>
                      <div className="text-[10px] text-[#6B6F7A]">Strict header check</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>

          </div>

        </div>
      </section>


      {/* ═══════════════════════════════════════════════════════════
           6. REGULATORY PIPELINE & ARCHITECTURE SHOWCASE
      ════════════════════════════════════════════════════════════ */}
      <section id="architecture" className="relative z-10 py-16 border-t border-[#DAD3C3] bg-white">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          
          <div className="text-center max-w-3xl mx-auto mb-12 space-y-2">
            <div className="inline-flex items-center gap-2 px-3 py-0.5 rounded-full bg-[#ECE7DD] border border-[#DAD3C3] text-xs font-mono text-[#22262E] uppercase tracking-wider font-semibold">
              Autonomous End-to-End Workflow
            </div>
            <h2 className="text-3xl sm:text-4xl font-bold text-[#22262E]">
              From Wire Ingestion to Regulatory Resolution
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
            
            <div className="p-6 rounded-xl bg-[#ECE7DD] border border-[#DAD3C3] space-y-3">
              <div className="text-3xl font-extrabold font-mono text-[#3D5A80]">01</div>
              <h3 className="text-lg font-bold text-[#22262E]">Ingest &amp; Enrich</h3>
              <p className="text-xs text-[#6B6F7A] leading-relaxed">
                Streaming queues ingest multi-currency wires, SWIFT MT/MX messages, and domestic clearing transactions with real-time sanctions list enrichment.
              </p>
            </div>

            <div className="p-6 rounded-xl bg-[#ECE7DD] border border-[#DAD3C3] space-y-3">
              <div className="text-3xl font-extrabold font-mono text-[#C98A2E]">02</div>
              <h3 className="text-lg font-bold text-[#22262E]">Cognitive Scoring</h3>
              <p className="text-xs text-[#6B6F7A] leading-relaxed">
                Multi-hop Neo4j graph topology and Isolation Forest behavioral models evaluate anomaly velocity and circular fund cycling in sub-50ms.
              </p>
            </div>

            <div className="p-6 rounded-xl bg-[#ECE7DD] border border-[#DAD3C3] space-y-3">
              <div className="text-3xl font-extrabold font-mono text-[#4C7A5E]">03</div>
              <h3 className="text-lg font-bold text-[#22262E]">Cockpit Triage &amp; Filing</h3>
              <p className="text-xs text-[#6B6F7A] leading-relaxed">
                Compliance investigators audit evidence with full SHAP transparency. Single hotkeys trigger verified false-positive dismissal or FinCEN SAR XML filing.
              </p>
            </div>

          </div>

          {/* Institutional Architecture Image Showcase */}
          <div className="mt-10 rounded-xl overflow-hidden border border-[#DAD3C3] p-2 bg-[#ECE7DD] shadow-md">
            <div className="relative rounded-lg overflow-hidden border border-[#DAD3C3] bg-[#1B1F2B]">
              <img
                src="/static/images/aml_landing_hero.jpg"
                alt="Sentinel Multi-Tier Financial Defense Architecture Diagram showing Kafka, Neo4j, and FinCEN interfaces"
                loading="lazy"
                decoding="async"
                className="w-full h-auto max-h-[440px] object-cover object-center"
              />
              <div className="absolute inset-0 bg-gradient-to-t from-[#1B1F2B]/90 via-transparent to-transparent flex items-end p-6">
                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between w-full gap-4">
                  <div>
                    <span className="px-2 py-0.5 rounded bg-[#3D5A80]/20 text-[#8BB9E0] border border-[#3D5A80]/40 text-[10px] font-mono font-bold uppercase">
                      System Topography
                    </span>
                    <h4 className="text-lg font-bold text-white mt-1">
                      Multi-Tenant Ingestion &amp; Regulatory Filing Core
                    </h4>
                    <p className="text-xs text-slate-300 font-mono">
                      Kafka / Redpanda Event Streams · Neo4j Cluster · FinCEN BSA SDX Gateway
                    </p>
                  </div>
                  <a
                    href="/dashboard"
                    className="px-4 py-2 rounded bg-white hover:bg-[#ECE7DD] text-[#1B1F2B] text-xs font-mono font-bold transition flex items-center gap-1.5 shadow"
                  >
                    <span>Test Live Engine</span>
                    <ArrowRight className="w-3.5 h-3.5" />
                  </a>
                </div>
              </div>
            </div>
          </div>

        </div>
      </section>


      {/* ═══════════════════════════════════════════════════════════
           7. INSTITUTIONAL PRICING & LICENSING
      ════════════════════════════════════════════════════════════ */}
      <section id="pricing" className="relative z-10 py-16 border-t border-[#DAD3C3] bg-[#ECE7DD]">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          
          <div className="text-center max-w-3xl mx-auto mb-12 space-y-2">
            <div className="inline-flex items-center gap-2 px-3 py-0.5 rounded-full bg-white border border-[#DAD3C3] text-xs font-mono text-[#3D5A80] uppercase tracking-wider font-semibold">
              Institutional Deployment
            </div>
            <h2 className="text-3xl sm:text-4xl font-bold text-[#22262E]">
              Sovereign Deployment Models
            </h2>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-5xl mx-auto">
            
            {/* Tier 1 */}
            <div className="rounded-xl p-6 bg-white border border-[#DAD3C3] shadow-sm flex flex-col justify-between">
              <div className="space-y-3">
                <div className="text-xs font-mono text-[#3D5A80] font-bold uppercase">Fintech Tier</div>
                <h3 className="text-xl font-bold text-[#22262E]">Cloud Multi-Tenant</h3>
                <p className="text-xs text-[#6B6F7A]">For licensed payment aggregators and neobanks under 2M tx/mo.</p>
                <div className="py-3 border-y border-[#DAD3C3]">
                  <span className="text-2xl font-bold font-mono text-[#1B1F2B]">$4,500</span>
                  <span className="text-xs text-[#6B6F7A] font-mono"> / month</span>
                </div>
                <ul className="text-xs font-mono text-[#6B6F7A] space-y-1.5">
                  <li>✓ Up to 2M tx/month</li>
                  <li>✓ Real-time OFAC radar</li>
                  <li>✓ 3-Pane Cockpit access</li>
                  <li>✓ 99.9% Ingestion SLA</li>
                </ul>
              </div>
              <a
                href="/dashboard"
                className="w-full mt-6 py-2 rounded text-center text-xs font-semibold text-[#1B1F2B] bg-[#ECE7DD] hover:bg-[#E2DDD1] border border-[#DAD3C3] transition"
              >
                Explore System Trial
              </a>
            </div>

            {/* Tier 2 (Featured) */}
            <div className="rounded-xl p-6 bg-white border-2 border-[#3D5A80] relative shadow-lg flex flex-col justify-between">
              <div className="absolute -top-2.5 left-1/2 -translate-x-1/2 px-2.5 py-0.5 rounded-full bg-[#3D5A80] text-white text-[9px] font-mono font-bold uppercase">
                ENTERPRISE PREFERRED
              </div>
              <div className="space-y-3">
                <div className="text-xs font-mono text-[#3D5A80] font-bold uppercase">Dedicated Virtual Cloud</div>
                <h3 className="text-xl font-bold text-[#22262E]">Enterprise Bank</h3>
                <p className="text-xs text-[#6B6F7A]">Single-tenant dedicated VPC infrastructure for regional and national banking lenders.</p>
                <div className="py-3 border-y border-[#DAD3C3]">
                  <span className="text-2xl font-bold font-mono text-[#1B1F2B]">$14,000</span>
                  <span className="text-xs text-[#6B6F7A] font-mono"> / month</span>
                </div>
                <ul className="text-xs font-mono text-[#6B6F7A] space-y-1.5">
                  <li>✓ Unlimited monthly transactions</li>
                  <li>✓ Full Neo4j 2-Hop Graph Topology</li>
                  <li>✓ Automated FinCEN BSA filing</li>
                  <li>✓ 24/7 Dedicated Support SLA</li>
                </ul>
              </div>
              <a
                href="/dashboard"
                className="w-full mt-6 py-2 rounded text-center text-xs font-semibold text-white bg-[#1B1F2B] hover:bg-[#2B3040] shadow-sm transition"
              >
                Deploy Dedicated Sandbox
              </a>
            </div>

            {/* Tier 3 */}
            <div className="rounded-xl p-6 bg-white border border-[#DAD3C3] shadow-sm flex flex-col justify-between">
              <div className="space-y-3">
                <div className="text-xs font-mono text-[#1B1F2B] font-bold uppercase">Air-Gapped Sovereign</div>
                <h3 className="text-xl font-bold text-[#22262E]">Central Bank / FIU</h3>
                <p className="text-xs text-[#6B6F7A]">For Tier-1 multinational institutions, central bank regulators, and sovereign agencies.</p>
                <div className="py-3 border-y border-[#DAD3C3]">
                  <span className="text-2xl font-bold font-mono text-[#1B1F2B]">Custom</span>
                  <span className="text-xs text-[#6B6F7A] font-mono"> / institutional MSA</span>
                </div>
                <ul className="text-xs font-mono text-[#6B6F7A] space-y-1.5">
                  <li>✓ Air-Gapped On-Premises Option</li>
                  <li>✓ Custom HSM Key Encryption</li>
                  <li>✓ Country FIU Transmit Connectors</li>
                  <li>✓ Source Code Audit License</li>
                </ul>
              </div>
              <button
                onClick={() => setVideoModalOpen(true)}
                aria-label="Schedule institutional architecture review"
                className="w-full mt-6 py-2 rounded text-center text-xs font-semibold text-[#1B1F2B] bg-[#ECE7DD] hover:bg-[#E2DDD1] border border-[#DAD3C3] transition"
              >
                Schedule Architecture Review
              </button>
            </div>

          </div>

        </div>
      </section>


      {/* ═══════════════════════════════════════════════════════════
           8. CHARCOAL-NAVY FOOTER (#1B1F2B)
      ════════════════════════════════════════════════════════════ */}
      <footer className="relative z-10 bg-[#1B1F2B] border-t border-[#2B3040] py-10 text-slate-300">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col md:flex-row items-center justify-between gap-6">
          
          <div className="flex items-center gap-3">
            <div className="w-7 h-7 rounded bg-[#2B3040] flex items-center justify-center text-white">
              <Shield className="w-4 h-4 text-[#4C7A5E]" />
            </div>
            <span className="text-sm font-bold text-white">SENTINEL AML</span>
            <span className="text-xs font-mono text-slate-400">| © 2026 Sovereign Compliance Core</span>
          </div>

          <div className="flex items-center gap-6 text-xs font-mono text-slate-300">
            <a href="/dashboard" className="hover:text-white transition">Investigation Cockpit</a>
            <a href="/login" className="hover:text-white transition">Analyst Portal</a>
            <a href="#threejs-section" className="hover:text-white transition">3D Topology Matrix</a>
            <a href="#cockpit-preview" className="hover:text-white transition">Video Tour</a>
          </div>

          <div className="flex items-center gap-2 text-xs font-mono text-[#4C7A5E]">
            <span className="w-2 h-2 rounded-full bg-[#4C7A5E] animate-pulse" />
            <span>All Compliance Engines Operational</span>
          </div>

        </div>
      </footer>


      {/* ═══════════════════════════════════════════════════════════
           9. VIDEO WALKTHROUGH MODAL WITH ACCESSIBILITY TRAP
      ════════════════════════════════════════════════════════════ */}
      <AnimatePresence>
        {videoModalOpen && (
          <div
            className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#1B1F2B]/80 backdrop-blur-md"
            role="dialog"
            aria-modal="true"
            aria-label="Sentinel AML Cockpit Case Walkthrough Video"
            onClick={(e) => {
              if (e.target === e.currentTarget) setVideoModalOpen(false);
            }}
          >
            <motion.div
              initial={{ scale: 0.95, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.95, opacity: 0 }}
              className="relative w-full max-w-3xl bg-white rounded-xl overflow-hidden border-2 border-[#DAD3C3] shadow-2xl"
            >
              <div className="flex items-center justify-between px-4 py-3 bg-[#1B1F2B] border-b border-[#2B3040] text-white">
                <div className="flex items-center gap-2 text-xs font-mono">
                  <PlayCircle className="w-4 h-4 text-[#4C7A5E]" />
                  <span>Sentinel AML Cockpit — Live Case Investigation Walkthrough</span>
                </div>
                <button
                  onClick={() => setVideoModalOpen(false)}
                  aria-label="Close video modal"
                  className="text-slate-400 hover:text-white focus:outline-none"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="p-6 bg-[#ECE7DD] space-y-4">
                {/* Video Demo Canvas */}
                <div className="aspect-[16/9] w-full rounded-lg overflow-hidden border border-[#DAD3C3] relative bg-[#1B1F2B] group">
                  <div className="relative w-full h-full">
                    <img
                      src="/static/images/aml_warm_cockpit.jpg"
                      alt="Live Investigation Walkthrough Video Frame"
                      className="w-full h-full object-cover opacity-85 filter contrast-105"
                    />

                    <div className="absolute inset-0 bg-gradient-to-t from-[#1B1F2B]/90 via-transparent to-[#1B1F2B]/40 pointer-events-none" />

                    {/* Video Top Bar */}
                    <div className="absolute top-3 left-3 flex items-center gap-2 px-2.5 py-1 rounded bg-[#1B1F2B]/85 border border-[#2B3040] text-xs font-mono text-white backdrop-blur">
                      <span className="w-2 h-2 rounded-full bg-[#C1443B] animate-ping" />
                      <span className="font-bold text-[#C1443B]">REC</span>
                      <span className="text-slate-400">|</span>
                      <span>CASE_WALKTHROUGH_04471.MP4</span>
                    </div>

                    <div className="absolute top-3 right-3 px-2.5 py-1 rounded bg-[#3D5A80]/90 text-white text-xs font-mono font-semibold backdrop-blur">
                      Step 2 of 4: Structuring Anomaly Audit
                    </div>

                    {/* Focus Target Spotlight Box */}
                    <div className="absolute top-1/4 left-1/4 w-1/2 h-1/2 border-2 border-[#C1443B] rounded pointer-events-none shadow-[0_0_20px_rgba(193,68,59,0.3)] animate-pulse flex items-start justify-end p-1.5">
                      <span className="px-1.5 py-0.5 rounded bg-[#C1443B] text-white text-[9px] font-mono font-bold">
                        ANOMALY DETECTED // 92%
                      </span>
                    </div>

                    {/* Bottom Video Controls */}
                    <div className="absolute bottom-0 inset-x-0 p-3 bg-gradient-to-t from-[#1B1F2B] via-[#1B1F2B]/95 to-transparent flex flex-col gap-2">
                      <div className="w-full bg-white/20 h-1.5 rounded-full overflow-hidden cursor-pointer relative">
                        <div className="bg-[#3D5A80] h-full w-[42%] rounded-full relative">
                          <span className="absolute right-0 top-1/2 -translate-y-1/2 w-3 h-3 rounded-full bg-white shadow" />
                        </div>
                      </div>

                      <div className="flex items-center justify-between text-white text-xs font-mono">
                        <div className="flex items-center gap-3">
                          <button
                            onClick={() => setIsPlayingDemo(!isPlayingDemo)}
                            aria-label={isPlayingDemo ? 'Pause video simulation' : 'Play video simulation'}
                            className="w-7 h-7 rounded-full bg-white text-[#1B1F2B] flex items-center justify-center hover:bg-slate-200 transition"
                          >
                            {isPlayingDemo ? <Pause className="w-3.5 h-3.5 fill-current" /> : <Play className="w-3.5 h-3.5 fill-current" />}
                          </button>
                          <span className="text-slate-300">00:44 / 01:45</span>
                          <span className="text-slate-400">·</span>
                          <span className="text-xs text-[#C98A2E] font-semibold">
                            Focus: Offshore Beneficiary Traversal
                          </span>
                        </div>

                        <div className="flex items-center gap-3 text-slate-300">
                          <span className="px-1.5 py-0.5 rounded bg-white/10 text-[10px]">1080p 60fps</span>
                          <Volume2 className="w-4 h-4 hover:text-white cursor-pointer" />
                          <Maximize2 className="w-4 h-4 hover:text-white cursor-pointer" />
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2 text-xs font-mono text-[#6B6F7A] pt-1">
                  <div>
                    <strong>Audio Transcript:</strong> &quot;Investigator selects Wire #9,480.00. Rule R-STRUCT-04 triggered. Neo4j shows 60% beneficial ownership linked to Cayman entity...&quot;
                  </div>
                  <a href="/dashboard" className="text-[#3D5A80] hover:underline font-bold whitespace-nowrap">
                    Launch Interactive Cockpit →
                  </a>
                </div>
              </div>
            </motion.div>
          </div>
        )}
      </AnimatePresence>

    </div>
  );
};

export default AmlLandingPage;
