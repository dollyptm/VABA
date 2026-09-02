from mcp.server.fastmcp import FastMCP
import requests

# Create an MCP server
mcp = FastMCP(
    name="CurrencyConverter",
    host="0.0.0.0",  # for SSE transport
    port=8050,
)

# Use a mock exchange rate for simplicity
EXCHANGE_RATES = {
    "USD": {"EUR": 0.91, "INR": 83.0},
    "EUR": {"USD": 1.1, "INR": 91.0},
    "INR": {"USD": 0.012, "EUR": 0.011}
}

@mcp.tool()
def convert_currency(amount: float, from_currency: str, to_currency: str) -> str:
    """
    Converts currency from one to another based on fixed exchange rates.
    """
    from_currency = from_currency.upper()
    to_currency = to_currency.upper()
    
    try:
        rate = EXCHANGE_RATES[from_currency][to_currency]
        converted = amount * rate
        return f"{amount:.2f} {from_currency} = {converted:.2f} {to_currency}"
    except KeyError:
        return f"Unsupported currency conversion: {from_currency} to {to_currency}"
    

#API_URL = "https://api.exchangerate.host/convert"

#@mcp.tool()
#def convert_currency(amount: float, from_currency: str, to_currency: str) -> str:
#    """
#    Converts currency using live exchange rates from exchangerate.host API.
#    """
#    from_currency = from_currency.upper()
#    to_currency = to_currency.upper()

#    response = requests.get(API_URL, params={
#        "from": from_currency,
#        "to": to_currency,
#        "amount": amount
#    })

#    if response.status_code != 200:
#        return f"Failed to fetch exchange rate (status {response.status_code})"

#    data = response.json()
#    if not data.get("success"):
#        return "Currency conversion failed or unsupported currencies."

#    result = data.get("result")
#    return f"{amount:.2f} {from_currency} = {result:.2f} {to_currency}"

# Run the server
if __name__ == "__main__":
    transport = "stdio"
    if transport == "stdio":
        print("Running server with stdio transport")
        mcp.run(transport="stdio")
    elif transport == "sse":
        print("Running server with SSE transport")
        mcp.run(transport="sse")
    else:
        raise ValueError(f"Unknown transport: {transport}")
