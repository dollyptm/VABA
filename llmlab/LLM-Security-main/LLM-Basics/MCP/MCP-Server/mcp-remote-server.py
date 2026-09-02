from mcp.server.fastmcp import FastMCP
import requests

# Create an MCP server
mcp = FastMCP(
    name="CurrencyConverter",
    host="0.0.0.0",  # Bind to all interfaces for remote connections
    port=8050
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
    

# Run the server
if __name__ == "__main__":
    transport = "sse"
    if transport == "stdio":
        print("Running server with stdio transport")
        mcp.run(transport="stdio")
    elif transport == "sse":
        print("Running server with SSE transport")
        mcp.run(transport="sse")
    else:
        raise ValueError(f"Unknown transport: {transport}")
