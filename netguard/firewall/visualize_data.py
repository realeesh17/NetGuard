from collections import defaultdict
from netguard.core.db import get_session
from netguard.core.models import FirewallDecision, FirewallRule

def get_sankey_data(limit: int = 200) -> dict:
    """
    Query the latest firewall decisions and format them as a Sankey diagram datasource.
    Flow matches: Source IP -> Rule Matched -> Action (Allow / Deny)
    
    Returns:
        A dictionary with "nodes" and "links" arrays.
    """
    with get_session() as session:
        # Load rules to map IDs to friendly descriptions
        rules = session.query(FirewallRule).all()
        rule_map = {r.id: f"Rule #{r.id} ({r.action.upper()} {r.protocol} to port {r.dst_port})" for r in rules}
        
        # Get latest decisions
        decisions = (
            session.query(FirewallDecision)
            .order_by(FirewallDecision.timestamp.desc())
            .limit(limit)
            .all()
        )
        
    if not decisions:
        return {"nodes": [], "links": []}
        
    # Aggregate flows
    # Flow 1: Source IP -> Rule
    src_to_rule = defaultdict(int)
    # Flow 2: Rule -> Action
    rule_to_action = defaultdict(int)
    
    for d in decisions:
        rule_name = rule_map.get(d.rule_matched_id, "Default Rule (DENY)")
        action_name = d.action_taken.upper()
        
        src_to_rule[(d.src_ip, rule_name)] += 1
        rule_to_action[(rule_name, action_name)] += 1
        
    # Build unique nodes list
    nodes_set = set()
    for src, rule in src_to_rule.keys():
        nodes_set.add(src)
        nodes_set.add(rule)
    for rule, action in rule_to_action.keys():
        nodes_set.add(rule)
        nodes_set.add(action)
        
    nodes_list = list(nodes_set)
    node_to_idx = {name: i for i, name in enumerate(nodes_list)}
    
    # Format nodes
    nodes = [{"name": name} for name in nodes_list]
    
    # Format links
    links = []
    for (src, rule), val in src_to_rule.items():
        links.append({
            "source": node_to_idx[src],
            "target": node_to_idx[rule],
            "value": val
        })
    for (rule, action), val in rule_to_action.items():
        links.append({
            "source": node_to_idx[rule],
            "target": node_to_idx[action],
            "value": val
        })
        
    return {"nodes": nodes, "links": links}
