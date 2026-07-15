import asyncio
import os
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.neo4j_db import get_async_neo4j_driver, close_async_neo4j_driver
from services.network_analysis import run_network_analysis, tarjan_scc, compute_betweenness_centrality

async def clear_neo4j_graph(session):
    print("Clearing test nodes and relationships in Neo4j...")
    # Delete test nodes and relations
    await session.run("MATCH (n:Account) WHERE n.account_number STARTS WITH 'NET_ACC_' DETACH DELETE n;")

async def seed_test_graph(session):
    print("Seeding graph for network analysis verification...")
    # 1. Seed a circular cycle: A -> B -> C -> A
    await session.run("MERGE (a:Account {id: 'net_a', account_number: 'NET_ACC_A'})")
    await session.run("MERGE (b:Account {id: 'net_b', account_number: 'NET_ACC_B'})")
    await session.run("MERGE (c:Account {id: 'net_c', account_number: 'NET_ACC_C'})")
    
    await session.run("MATCH (a:Account {id: 'net_a'}), (b:Account {id: 'net_b'}) MERGE (a)-[:TRANSFERS_TO]->(b)")
    await session.run("MATCH (b:Account {id: 'net_b'}), (c:Account {id: 'net_c'}) MERGE (b)-[:TRANSFERS_TO]->(c)")
    await session.run("MATCH (c:Account {id: 'net_c'}), (a:Account {id: 'net_a'}) MERGE (c)-[:TRANSFERS_TO]->(a)")

    # 2. Seed a Fan-In (Potential Mule): D, E, F -> G (with G only dispersing to H)
    await session.run("MERGE (d:Account {id: 'net_d', account_number: 'NET_ACC_D'})")
    await session.run("MERGE (e:Account {id: 'net_e', account_number: 'NET_ACC_E'})")
    await session.run("MERGE (f:Account {id: 'net_f', account_number: 'NET_ACC_F'})")
    await session.run("MERGE (g:Account {id: 'net_g', account_number: 'NET_ACC_G'})")
    await session.run("MERGE (h:Account {id: 'net_h', account_number: 'NET_ACC_H'})")
    
    await session.run("MATCH (d:Account {id: 'net_d'}), (g:Account {id: 'net_g'}) MERGE (d)-[:TRANSFERS_TO]->(g)")
    await session.run("MATCH (e:Account {id: 'net_e'}), (g:Account {id: 'net_g'}) MERGE (e)-[:TRANSFERS_TO]->(g)")
    await session.run("MATCH (f:Account {id: 'net_f'}), (g:Account {id: 'net_g'}) MERGE (f)-[:TRANSFERS_TO]->(g)")
    await session.run("MATCH (g:Account {id: 'net_g'}), (h:Account {id: 'net_h'}) MERGE (g)-[:TRANSFERS_TO]->(h)")

    # 3. Seed a Fan-Out (Layering): I -> J, K, L
    await session.run("MERGE (i:Account {id: 'net_i', account_number: 'NET_ACC_I'})")
    await session.run("MERGE (j:Account {id: 'net_j', account_number: 'NET_ACC_J'})")
    await session.run("MERGE (k:Account {id: 'net_k', account_number: 'NET_ACC_K'})")
    await session.run("MERGE (l:Account {id: 'net_l', account_number: 'NET_ACC_L'})")
    
    await session.run("MATCH (i:Account {id: 'net_i'}), (j:Account {id: 'net_j'}) MERGE (i)-[:TRANSFERS_TO]->(j)")
    await session.run("MATCH (i:Account {id: 'net_i'}), (k:Account {id: 'net_k'}) MERGE (i)-[:TRANSFERS_TO]->(k)")
    await session.run("MATCH (i:Account {id: 'net_i'}), (l:Account {id: 'net_l'}) MERGE (i)-[:TRANSFERS_TO]->(l)")

    # 4. Seed an Intermediary: X -> Y -> Z (Y should have Betweenness Centrality)
    await session.run("MERGE (x:Account {id: 'net_x', account_number: 'NET_ACC_X'})")
    await session.run("MERGE (y:Account {id: 'net_y', account_number: 'NET_ACC_Y'})")
    await session.run("MERGE (z:Account {id: 'net_z', account_number: 'NET_ACC_Z'})")
    
    await session.run("MATCH (x:Account {id: 'net_x'}), (y:Account {id: 'net_y'}) MERGE (x)-[:TRANSFERS_TO]->(y)")
    await session.run("MATCH (y:Account {id: 'net_y'}), (z:Account {id: 'net_z'}) MERGE (y)-[:TRANSFERS_TO]->(z)")

async def run_tests():
    driver = await get_async_neo4j_driver()
    async with driver.session() as session:
        await clear_neo4j_graph(session)
        await seed_test_graph(session)
        
        print("\nRunning network analysis on seeded Neo4j graph...")
        analysis = await run_network_analysis()
        
        # Test 1: Cycle / Strongly Connected Component detection
        print("\n--- Test 1: Cycle (Tarjan SCC) Detection ---")
        circular_flows = analysis["circular_flows"]
        print(f"Detected circular flows: {circular_flows}")
        assert len(circular_flows) > 0
        # Find the seeded cycle in the list of detected circular flows
        target_cycle = None
        for cf in circular_flows:
            if "NET_ACC_A" in cf["cycle"]:
                target_cycle = cf["cycle"]
                break
        assert target_cycle is not None
        assert "NET_ACC_B" in target_cycle
        assert "NET_ACC_C" in target_cycle
        
        # Test 2: Fan-In pattern detection
        print("\n--- Test 2: Fan-In Alert Detection ---")
        fan_in_alerts = analysis["fan_in_alerts"]
        print(f"Fan-in alerts: {fan_in_alerts}")
        assert len(fan_in_alerts) > 0
        alert_accounts = [alert["account_number"] for alert in fan_in_alerts]
        assert "NET_ACC_G" in alert_accounts
        
        # Test 3: Fan-Out pattern detection
        print("\n--- Test 3: Fan-Out Alert Detection ---")
        fan_out_alerts = analysis["fan_out_alerts"]
        print(f"Fan-out alerts: {fan_out_alerts}")
        assert len(fan_out_alerts) > 0
        alert_out_accounts = [alert["account_number"] for alert in fan_out_alerts]
        assert "NET_ACC_I" in alert_out_accounts
        
        # Test 4: Intermediary betweenness centrality
        print("\n--- Test 4: Transit Intermediary (Betweenness Centrality) Ranking ---")
        ranking = analysis["intermediary_ranking"]
        print(f"Central intermediary nodes: {ranking}")
        assert len(ranking) > 0
        central_nodes = [node["account_number"] for node in ranking]
        # NET_ACC_Y should be in the ranking as it lies on the path between X and Z
        assert "NET_ACC_Y" in central_nodes
        
        # Clean up
        await clear_neo4j_graph(session)

    await close_async_neo4j_driver()
    print("\n=== ALL GRAPH NETWORK VERIFICATION TESTS PASSED SUCCESSFULLY! ===")

if __name__ == "__main__":
    asyncio.run(run_tests())
