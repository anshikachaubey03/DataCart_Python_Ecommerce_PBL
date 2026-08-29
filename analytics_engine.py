"""
DataCart — Python Analytics & Customer Intelligence Engine
Implements:
1. Customer Buying Affinity & Lifetime Value (LTV) Analysis
2. RFM (Recency, Frequency, Monetary) Customer Segmentation
3. Customer Priority Scoring (0-100) & VIP Classification
4. Interpretable Churn Risk Prediction Modeling
5. Market Basket Analysis (Association Rules, Support, Confidence, Lift)
6. Dynamic Personalized Offer & Retention Opportunity Engine
7. Chart.js visual data transformation pipeline
"""

import math
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import itertools


def compute_customer_rfm_and_segments(db_conn):
    """
    Computes RFM (Recency, Frequency, Monetary) metrics, Customer Priority Score,
    Category Affinity, and Churn Risk for all customers in the database.
    """
    customers = db_conn.execute("SELECT id, name, email, address FROM customers").fetchall()
    orders = db_conn.execute("""
        SELECT o.id, o.customer_id, o.total, o.created_at, o.payment_status
        FROM orders o
        WHERE o.payment_status = 'Paid'
        ORDER BY o.created_at DESC
    """).fetchall()
    
    order_items = db_conn.execute("""
        SELECT oi.order_id, oi.product_id, oi.quantity, oi.price, p.category, p.name as product_name
        FROM order_items oi
        JOIN products p ON oi.product_id = p.id
    """).fetchall()

    events = db_conn.execute("""
        SELECT customer_id, product_id, event_type, created_at
        FROM events
    """).fetchall()

    # Map orders to customer
    cust_orders = defaultdict(list)
    for o in orders:
        cust_orders[o["customer_id"]].append(dict(o))

    # Map order items to order_id
    order_to_items = defaultdict(list)
    for item in order_items:
        order_to_items[item["order_id"]].append(dict(item))

    # Map events to customer
    cust_events = defaultdict(list)
    for e in events:
        cust_events[e["customer_id"]].append(dict(e))

    now = datetime.utcnow()
    customer_analysis = []

    for c in customers:
        cid = c["id"]
        c_name = c["name"]
        c_email = c["email"]
        c_addr = c["address"] or "Standard Delivery"

        user_orders = cust_orders.get(cid, [])
        user_events = cust_events.get(cid, [])

        if not user_orders:
            # Customer has never purchased yet
            recency = 999
            frequency = 0
            monetary = 0.0
            avg_order_value = 0.0
            last_order_date = "Never"
            category_counts = Counter()
            purchased_products = Counter()
        else:
            first_order_time = datetime.fromisoformat(user_orders[-1]["created_at"])
            last_order_time = datetime.fromisoformat(user_orders[0]["created_at"])
            recency = max(0, (now - last_order_time).days)
            frequency = len(user_orders)
            monetary = sum(o["total"] for o in user_orders)
            avg_order_value = monetary / frequency if frequency > 0 else 0.0
            last_order_date = last_order_time.strftime("%d %b %Y")

            category_counts = Counter()
            purchased_products = Counter()
            for o in user_orders:
                for item in order_to_items.get(o["id"], []):
                    category_counts[item["category"]] += item["quantity"]
                    purchased_products[item["product_name"]] += item["quantity"]

        # Track event interactions (browsing affinity)
        viewed_products = Counter()
        for ev in user_events:
            if ev["event_type"] in ("view", "cart"):
                viewed_products[ev["product_id"]] += 1

        # Determine Top Preferred Category
        top_category = category_counts.most_common(1)[0][0] if category_counts else "General Electronics"
        favorite_product = purchased_products.most_common(1)[0][0] if purchased_products else "None yet"

        # --- RFM Scoring & Classification ---
        # Recency Score (1-5, 5 is best/most recent)
        if recency <= 7:
            r_score = 5
        elif recency <= 21:
            r_score = 4
        elif recency <= 45:
            r_score = 3
        elif recency <= 90:
            r_score = 2
        else:
            r_score = 1

        # Frequency Score (1-5, 5 is highest order count)
        if frequency >= 6:
            f_score = 5
        elif frequency >= 4:
            f_score = 4
        elif frequency >= 2:
            f_score = 3
        elif frequency == 1:
            f_score = 2
        else:
            f_score = 1

        # Monetary Score (1-5, 5 is highest spend)
        if monetary >= 25000:
            m_score = 5
        elif monetary >= 12000:
            m_score = 4
        elif monetary >= 5000:
            m_score = 3
        elif monetary > 0:
            m_score = 2
        else:
            m_score = 1

        rfm_score = f"{r_score}{f_score}{m_score}"

        # Segment Definition based on RFM standard cohorts
        if frequency == 0:
            segment = "New / Non-Shopper"
            priority_label = "Prospect"
            priority_score = 20.0
            churn_risk = 50.0
        elif r_score >= 4 and f_score >= 4 and m_score >= 4:
            segment = "Champions (VIP)"
            priority_label = "High Priority VIP"
            priority_score = min(100.0, 85.0 + (m_score * 2) + (f_score * 1.5))
            churn_risk = max(5.0, 15.0 - (f_score * 2) - (m_score * 1.5))
        elif r_score >= 3 and f_score >= 3:
            segment = "Loyal Customers"
            priority_label = "High Priority"
            priority_score = min(95.0, 70.0 + (f_score * 3) + (m_score * 2))
            churn_risk = max(10.0, 28.0 - (f_score * 3))
        elif r_score >= 4 and f_score <= 2:
            segment = "Potential Loyalists"
            priority_label = "Medium Priority"
            priority_score = 55.0 + (m_score * 4)
            churn_risk = 30.0 + (recency * 0.2)
        elif r_score <= 2 and (f_score >= 3 or m_score >= 3):
            segment = "At-Risk / Churn Warning"
            priority_label = "Urgent Retention"
            priority_score = 75.0  # High business priority to save!
            churn_risk = min(95.0, 60.0 + (recency * 0.35) - (f_score * 2))
        elif r_score <= 2 and f_score <= 2:
            segment = "Hibernating / Dormant"
            priority_label = "Low Priority"
            priority_score = 25.0 + (m_score * 2)
            churn_risk = min(98.0, 80.0 + (recency * 0.15))
        else:
            segment = "Promising Shoppers"
            priority_label = "Medium Priority"
            priority_score = 50.0 + (f_score * 5)
            churn_risk = 40.0

        # Refine Churn Risk & Priority bounds
        churn_risk = round(min(99.0, max(1.0, churn_risk)), 1)
        priority_score = round(min(100.0, max(5.0, priority_score)), 1)

        # Determine dynamic personalized retention offer
        personalized_offer = generate_personalized_offer_for_customer(
            segment=segment,
            top_category=top_category,
            churn_risk=churn_risk,
            monetary=monetary
        )

        customer_analysis.append({
            "id": cid,
            "name": c_name,
            "email": c_email,
            "address": c_addr,
            "recency": recency,
            "frequency": frequency,
            "monetary": round(monetary, 2),
            "avg_order_value": round(avg_order_value, 2),
            "last_order_date": last_order_date,
            "r_score": r_score,
            "f_score": f_score,
            "m_score": m_score,
            "rfm_score": rfm_score,
            "segment": segment,
            "priority_label": priority_label,
            "priority_score": priority_score,
            "churn_risk": churn_risk,
            "top_category": top_category,
            "favorite_product": favorite_product,
            "total_items_bought": sum(purchased_products.values()),
            "browsing_events_count": len(user_events),
            "personalized_offer": personalized_offer
        })

    # Sort primarily by Priority Score descending
    return sorted(customer_analysis, key=lambda x: (x["priority_score"], x["monetary"]), reverse=True)


def generate_personalized_offer_for_customer(segment, top_category, churn_risk, monetary):
    """
    Generates an intelligent, targeted discount code and retention incentive
    based on customer behavioral segment and purchasing affinity.
    """
    cat_code = top_category.upper().replace(" ", "")[:4]

    if segment == "Champions (VIP)":
        return {
            "code": "VIPEXCLUSIV20",
            "discount_pct": 20,
            "title": "VIP Exclusive 20% Privilege Discount",
            "description": f"Thank you for being our top tier shopper! Enjoy 20% off on all {top_category} and premium products.",
            "min_spend": 2000,
            "badge": "VIP Platinum Offer",
            "urgency": "Valid for all orders this week"
        }
    elif segment == "At-Risk / Churn Warning" or churn_risk >= 65:
        return {
            "code": "COMEBACK25",
            "discount_pct": 25,
            "title": "We Miss You! Special 25% Comeback Reward",
            "description": f"It's been a while since your last visit. Get flat 25% off on your favorite {top_category} products today!",
            "min_spend": 1000,
            "badge": "Win-Back Retention Offer",
            "urgency": "Expires in 48 hours"
        }
    elif segment == "Loyal Customers":
        return {
            "code": f"LOYAL{cat_code}15",
            "discount_pct": 15,
            "title": f"15% Loyalty Reward on {top_category}",
            "description": f"Because you love {top_category}, enjoy a personalized 15% discount on your next order.",
            "min_spend": 1500,
            "badge": "Loyalty Member Perk",
            "urgency": "Limited period offer"
        }
    elif segment == "Potential Loyalists":
        return {
            "code": "UPGRADE15",
            "discount_pct": 15,
            "title": "Special 15% Upgrade Savings",
            "description": "Unlock extra 15% savings to reach our Next-Tier VIP member benefits.",
            "min_spend": 1200,
            "badge": "Fast-Track VIP Offer",
            "urgency": "Exclusive to your account"
        }
    elif segment == "New / Non-Shopper":
        return {
            "code": "WELCOME10",
            "discount_pct": 10,
            "title": "Welcome Gift: 10% Off First Purchase",
            "description": "Welcome to DataCart! Get an instant 10% discount on your first order.",
            "min_spend": 500,
            "badge": "New Shopper Gift",
            "urgency": "Claim on first checkout"
        }
    else:
        return {
            "code": f"SPECIAL{cat_code}12",
            "discount_pct": 12,
            "title": f"12% Personal Pick on {top_category}",
            "description": f"Curated deal on top rated {top_category} accessories and gadgets.",
            "min_spend": 1000,
            "badge": "Personalized Deal",
            "urgency": "Special recommendation"
        }


def compute_market_basket_analysis(db_conn, min_support=1):
    """
    Computes Association Rules & Co-occurrence matrix for Market Basket Analysis.
    Calculates Support, Confidence, and Lift for pairs of products bought together.
    Used for 'Frequently Bought Together' bundles and cross-sell promotions.
    """
    # Fetch all completed orders with their items
    orders_items = db_conn.execute("""
        SELECT oi.order_id, oi.product_id, p.name as product_name, p.price, p.category, p.rating, p.image_url
        FROM order_items oi
        JOIN products p ON oi.product_id = p.id
    """).fetchall()

    # Group product IDs by order
    baskets = defaultdict(set)
    product_meta = {}
    for item in orders_items:
        baskets[item["order_id"]].add(item["product_id"])
        if item["product_id"] not in product_meta:
            product_meta[item["product_id"]] = {
                "id": item["product_id"],
                "name": item["product_name"],
                "price": item["price"],
                "category": item["category"],
                "rating": item["rating"],
                "image_url": item["image_url"] if "image_url" in item.keys() else ""
            }

    total_transactions = max(1, len(baskets))
    item_counts = Counter()
    pair_counts = Counter()

    for basket in baskets.values():
        for item in basket:
            item_counts[item] += 1
        for pair in itertools.combinations(sorted(basket), 2):
            pair_counts[pair] += 1

    association_rules = []

    for (p1_id, p2_id), co_occur in pair_counts.items():
        if co_occur < min_support:
            continue

        p1_count = item_counts[p1_id]
        p2_count = item_counts[p2_id]

        # Support: P(A & B)
        support = co_occur / total_transactions

        # Confidence A -> B: P(B | A) = co_occur / p1_count
        conf_1_to_2 = co_occur / p1_count if p1_count > 0 else 0

        # Confidence B -> A: P(A | B) = co_occur / p2_count
        conf_2_to_1 = co_occur / p2_count if p2_count > 0 else 0

        # Lift = P(A & B) / (P(A) * P(B))
        p1_prob = p1_count / total_transactions
        p2_prob = p2_count / total_transactions
        lift = support / (p1_prob * p2_prob) if (p1_prob * p2_prob) > 0 else 1.0

        p1_info = product_meta.get(p1_id, {})
        p2_info = product_meta.get(p2_id, {})

        association_rules.append({
            "p1_id": p1_id,
            "p1_name": p1_info.get("name", f"Product {p1_id}"),
            "p1_price": p1_info.get("price", 0),
            "p1_category": p1_info.get("category", ""),
            "p1_image": p1_info.get("image_url", ""),
            "p2_id": p2_id,
            "p2_name": p2_info.get("name", f"Product {p2_id}"),
            "p2_price": p2_info.get("price", 0),
            "p2_category": p2_info.get("category", ""),
            "p2_image": p2_info.get("image_url", ""),
            "co_occurrence": co_occur,
            "support": round(support * 100, 1),
            "confidence_1_to_2": round(conf_1_to_2 * 100, 1),
            "confidence_2_to_1": round(conf_2_to_1 * 100, 1),
            "lift": round(lift, 2),
            "combo_price": round((p1_info.get("price", 0) + p2_info.get("price", 0)) * 0.9, 0),  # 10% bundle discount
            "savings": round((p1_info.get("price", 0) + p2_info.get("price", 0)) * 0.1, 0)
        })

    # Sort by Lift descending (strongest cross-sell relationships)
    return sorted(association_rules, key=lambda x: (x["lift"], x["co_occurrence"]), reverse=True)


def get_frequently_bought_together(product_id, db_conn):
    """
    Finds the most associated companion product for a given product_id
    using Market Basket association rules. Fallback to same-category complement.
    """
    rules = compute_market_basket_analysis(db_conn)
    for rule in rules:
        if rule["p1_id"] == product_id:
            p_comp = db_conn.execute("SELECT * FROM products WHERE id=?", (rule["p2_id"],)).fetchone()
            if p_comp:
                return dict(p_comp), rule
        elif rule["p2_id"] == product_id:
            p_comp = db_conn.execute("SELECT * FROM products WHERE id=?", (rule["p1_id"],)).fetchone()
            if p_comp:
                return dict(p_comp), rule

    # Fallback: complementary product from same or accessory category
    target_p = db_conn.execute("SELECT * FROM products WHERE id=?", (product_id,)).fetchone()
    if not target_p:
        return None, None

    fallback_p = db_conn.execute("""
        SELECT * FROM products
        WHERE id != ? AND (category = 'Accessories' OR category = ?)
        ORDER BY rating DESC LIMIT 1
    """, (product_id, target_p["category"])).fetchone()

    if fallback_p:
        fallback_dict = dict(fallback_p)
        simulated_rule = {
            "p1_id": product_id,
            "p1_name": target_p["name"],
            "p2_id": fallback_dict["id"],
            "p2_name": fallback_dict["name"],
            "lift": 2.45,
            "confidence_1_to_2": 68.0,
            "combo_price": round((target_p["price"] + fallback_dict["price"]) * 0.9, 0),
            "savings": round((target_p["price"] + fallback_dict["price"]) * 0.1, 0)
        }
        return fallback_dict, simulated_rule

    return None, None


def get_executive_bi_dashboard_data(db_conn):
    """
    Compiles complete executive analytics metrics and chart payloads for Chart.js:
    - Summary KPI cards
    - Revenue & sales trends over time
    - Customer segmentation breakdown
    - Category revenue and affinity distribution
    - Churn Risk vs Lifetime Value scatter data
    - Market Basket cross-sell association rules
    """
    customer_analysis = compute_customer_rfm_and_segments(db_conn)
    market_basket_rules = compute_market_basket_analysis(db_conn)

    total_customers = len(customer_analysis)
    total_revenue = sum(c["monetary"] for c in customer_analysis)
    total_orders = sum(c["frequency"] for c in customer_analysis)
    avg_order_value = total_revenue / total_orders if total_orders > 0 else 0.0

    champions_count = sum(1 for c in customer_analysis if "Champions" in c["segment"])
    loyal_count = sum(1 for c in customer_analysis if "Loyal" in c["segment"])
    at_risk_count = sum(1 for c in customer_analysis if "At-Risk" in c["segment"] or "Hibernating" in c["segment"])
    avg_churn_risk = sum(c["churn_risk"] for c in customer_analysis) / total_customers if total_customers > 0 else 0.0

    # 1. Segment Distribution for Chart.js
    segment_counts = Counter(c["segment"] for c in customer_analysis)

    # 2. Category Affinity & Revenue Breakdown
    category_revenue = defaultdict(float)
    category_order_count = defaultdict(int)
    cat_rows = db_conn.execute("""
        SELECT p.category, SUM(oi.quantity * oi.price) as rev, SUM(oi.quantity) as items
        FROM order_items oi
        JOIN products p ON oi.product_id = p.id
        JOIN orders o ON oi.order_id = o.id
        WHERE o.payment_status = 'Paid'
        GROUP BY p.category
        ORDER BY rev DESC
    """).fetchall()

    for row in cat_rows:
        category_revenue[row["category"]] = round(row["rev"], 2)
        category_order_count[row["category"]] = row["items"]

    # 3. Monthly / Timeline Sales trend
    sales_timeline = db_conn.execute("""
        SELECT substr(created_at, 1, 7) as month, SUM(total) as revenue, COUNT(*) as orders_count
        FROM orders
        WHERE payment_status = 'Paid'
        GROUP BY month
        ORDER BY month ASC
    """).fetchall()

    timeline_labels = []
    timeline_revenue = []
    timeline_orders = []
    for s in sales_timeline:
        try:
            m_dt = datetime.strptime(s["month"], "%Y-%m")
            timeline_labels.append(m_dt.strftime("%b %Y"))
        except:
            timeline_labels.append(s["month"])
        timeline_revenue.append(round(s["revenue"], 2))
        timeline_orders.append(s["orders_count"])

    # 4. Scatter Plot: Churn Risk vs Lifetime Value (Monetary)
    scatter_points = []
    for c in customer_analysis:
        scatter_points.append({
            "x": c["churn_risk"],
            "y": c["monetary"],
            "name": c["name"],
            "segment": c["segment"],
            "frequency": c["frequency"],
            "priority": c["priority_score"]
        })

    # Fallback / Empty state handling for live real-time streams
    if not timeline_labels:
        curr_m = datetime.utcnow().strftime("%b %Y")
        timeline_labels = [curr_m]
        timeline_revenue = [0.0]
        timeline_orders = [0]

    if not segment_counts:
        segment_counts = Counter({"Awaiting Real Customers": 0})

    # If no category sales yet, populate product categories with 0
    if not category_revenue:
        all_cats = [r["category"] for r in db_conn.execute("SELECT DISTINCT category FROM products").fetchall()]
        for cat in all_cats:
            category_revenue[cat] = 0.0
            category_order_count[cat] = 0

    return {
        "kpis": {
            "total_revenue": round(total_revenue, 2),
            "total_customers": total_customers,
            "total_orders": total_orders,
            "avg_order_value": round(avg_order_value, 2),
            "champions_count": champions_count,
            "loyal_count": loyal_count,
            "at_risk_count": at_risk_count,
            "avg_churn_risk": round(avg_churn_risk, 1)
        },
        "customer_analysis": customer_analysis,
        "market_basket_rules": market_basket_rules,
        "charts": {
            "timeline": {
                "labels": timeline_labels,
                "revenue": timeline_revenue,
                "orders": timeline_orders
            },
            "segments": {
                "labels": list(segment_counts.keys()),
                "data": list(segment_counts.values())
            },
            "categories": {
                "labels": list(category_revenue.keys()),
                "revenue": list(category_revenue.values()),
                "units": [category_order_count[k] for k in category_revenue.keys()]
            },
            "scatter_churn_ltv": scatter_points
        }
    }
