# DataCart ⚡ — Amazon-Style Python E-Commerce Platform with Customer Behavior Analytics

An intellectual, descriptive, and interactive E-Commerce web platform built in **Pure Python**, inspired by **Amazon's** user experience and focused heavily on **Customer Data Analytics, RFM Segmentation, Churn Prediction, and Personalized Retention Offers**.

---

## 🌟 Core Features & Architecture

### 1. Amazon-Inspired User Interface & Shopping Experience
- **Amazon Header Navigation**: Dark navy `#131921` header with delivery location indicator, universal search bar with category filter, "Hello, [Name] / Account & Lists", "Returns & Orders", and real-time numeric cart badge.
- **Secondary Sub-Navbar**: Direct links to *Today's Deals*, *Customer Analytics Hub*, *Computers & Laptops*, *Audio*, *Accessories*, *Books*, and *Gaming*.
- **Amazon Home Feed**: Promotional hero carousel, multi-tile category spotlight cards, AI-driven personalized recommendations ("Recommended based on your activity"), and trending best sellers.
- **Product Detail Page**: High-resolution image view, star rating breakdowns, verified customer reviews, prime delivery promise, and real-time inventory counters.
- **"Frequently Bought Together" Combo Bundle**: Amazon-style cross-sell widget powered by **Market Basket Analysis** with an instant 1-click bundle purchase button (10% combo savings).
- **Cart & Simulated 1-Click Checkout**: Free delivery threshold progress bar, dynamic discount coupon application, tokenized payment methods (Amazon Pay UPI, Cards, COD), and tracking IDs.

---

### 2. Python Data Science & Customer Analytics Engine (`analytics_engine.py`)

All data science and statistical operations are implemented in pure Python (`pandas`, `numpy`, `scikit-learn`, `sqlite3`):

1. **Customer Buying Affinity & Lifetime Value (LTV)**:
   - Tracks total customer spend, average order value (AOV), order count, and purchase velocity.
   - Discovers each customer's most preferred category and preferred product tier.
   - Computes a composite **Customer Priority Score (0–100)** to prioritize high-value shoppers.

2. **RFM Customer Segmentation & Churn Risk Modeling**:
   - Computes **Recency** (days since last purchase), **Frequency** (order count), and **Monetary** (total spent).
   - Automatically segments shoppers into standard behavioral cohorts:
     - 🏆 **Champions (VIP)**: High spend, frequent buyers, low recency (Priority 85–100).
     - 💎 **Loyal Customers**: Steady repeat shoppers across specific categories.
     - 🚀 **Potential Loyalists**: Recent shoppers with high basket potential.
     - ⚠️ **At-Risk / Churn Alert**: High past spending but prolonged inactivity (>90 days).
     - 💤 **Hibernating / Dormant**: Inactive accounts with low frequency.
     - 🌱 **New / Non-Shoppers**: Newly registered users ready for welcome incentives.
   - Predictive Churn Risk % scoring with visual risk meters.

3. **Market Basket Analysis (Association Rules & Lift Mining)**:
   - Computes product pair co-occurrences, **Support**, **Confidence**, and **Lift**:
     $$\text{Lift}(A \rightarrow B) = \frac{P(A \cap B)}{P(A) \cdot P(B)}$$
   - Identifies high-affinity companion products and powers the **"Frequently Bought Together"** bundle deals.

4. **Dynamic Personalized Retention Offers**:
   - Generates tailored promotion vouchers based on customer cohort and category preference:
     - `VIPEXCLUSIV20` — 20% privilege discount for VIP Champions.
     - `COMEBACK25` — 25% win-back incentive for At-Risk customers.
     - `LOYAL[CAT]15` — 15% category loyalty reward for top category shoppers.
     - `WELCOME10` — 10% first-order discount for new users.
     - `BUNDLE10` — 10% combo discount for complementary accessories.

---

### 3. Executive Business Intelligence Dashboard (`/analytics`)
- **Key Executive KPIs**: Total Platform Revenue (GMV), Active Shoppers, VIP Champions, Average Basket Size, and Churn Risk %.
- **Interactive Chart.js Visualizations**:
  1. *Monthly Revenue & Order Volume Timeline* (Line + Bar dual axis chart).
  2. *RFM Customer Segmentation Cohort Breakdown* (Doughnut chart).
  3. *Category Revenue & Affinity Contribution* (Bar chart).
  4. *Customer Lifetime Value (LTV) vs. Churn Risk %* (Scatter plot).
- **Searchable Customer Prioritization Matrix**: Filter by name, category, or segment, inspect RFM parameters, and open deep-dive profile modals.
- **Retention Campaign Simulator**: Simulate projected win-back revenue from triggering targeted customer retention campaigns.

---

## 🚀 How to Run the Project

### Prerequisites
- Python 3.10+ installed on your system.

### Steps (Windows PowerShell / Command Prompt)

1. **Activate the Virtual Environment**:
   ```powershell
   .venv\Scripts\Activate.ps1
   ```

2. **Install Dependencies**:
   ```powershell
   pip install -r requirements.txt
   ```

3. **Start the Web Application**:
   ```powershell
   python app.py
   ```

4. **Open in Browser**:
   ```
   http://127.0.0.1:5000
   ```

---

## 👥 One-Click Demo Personas (For Instant Testing)

Navigate to `/login` or use the footer links to instantly switch between customer personas and see how recommendations and dynamic offers change in real-time:

| Customer Persona | Segment | Recency | Orders | Total Spend | Personalized Offer |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Aarav Sharma** | 🏆 Champions (VIP) | 3 days | 6 | ₹1,28,000+ | `VIPEXCLUSIV20` (20% OFF) |
| **Priya Patel** | 💎 Loyal Shopper | 12 days | 4 | ₹54,000+ | `LOYALAUDI15` (15% OFF) |
| **Rohan Verma** | ⚠️ At-Risk Churn Alert | 105 days | 2 | ₹1,12,000+ | `COMEBACK25` (25% OFF) |
| **Ananya Iyer** | 🚀 Potential Loyalist | 5 days | 2 | ₹44,000+ | `UPGRADE15` (15% OFF) |
| **Neha Singh** | 🌱 New Non-Shopper | N/A | 0 | ₹0 | `WELCOME10` (10% OFF) |

---

## 🛠️ Project Structure

```
DataCart_Python_Ecommerce_PBL/
│
├── app.py                      # Flask presentation layer, routing, and database seeding
├── analytics_engine.py         # Pure Python Data Science engine (RFM, Churn, Market Basket, Offers)
├── ecommerce.db                # SQLite database (Products, Orders, Customers, Events, Reviews)
├── requirements.txt            # Python dependencies (Flask, Pandas, NumPy, Scikit-Learn)
├── README.md                   # Project documentation and user guide
│
├── static/
│   └── style.css               # Amazon-style design system and BI dashboard styles
│
└── templates/
    ├── base.html               # Amazon header, search bar, sub-nav, user banner, footer
    ├── home.html               # Amazon home feed, hero banner, category tiles, product catalog
    ├── product.html            # Product page with "Frequently Bought Together" combo section
    ├── cart.html               # Cart with dynamic AI coupon suggestions & subtotal
    ├── checkout.html           # 1-Click checkout with payment tokenization
    ├── orders.html             # "Your Orders" tracking history
    ├── offers.html             # Dedicated personalized deals & vouchers page
    ├── analytics.html          # Executive BI dashboard with Chart.js & Customer Deep-Dive modal
    ├── auth.html               # Sign-in / Register with 1-click persona switcher
    └── success.html            # Order confirmation receipt with tracking ID
```
