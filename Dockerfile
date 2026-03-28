FROM python:3.12-slim

WORKDIR /app

# Install the easy-llm-tools library
COPY src/easy_llm_tools/ /app/src/easy_llm_tools/
COPY pyproject.toml /app/
RUN pip install --no-cache-dir .

# Install MCP server dependencies
RUN pip install --no-cache-dir mcp

# Copy the MCP server
COPY src/easy_llm_tools_mcp/server.py /app/server.py

# Install tool dependencies
COPY tools/mcp_requirements.txt /app/tools/requirements.txt
RUN pip install --no-cache-dir -r /app/tools/requirements.txt

# Copy tools (only mcp_ prefixed files are loaded, but helpers are needed too)
COPY tools/helpers/ /app/tools/helpers/
COPY tools/mcp_*_tool.py /app/tools/
COPY tools/mcp.env /app/tools/.env
RUN chmod 600 /app/tools/.env
RUN mkdir -p /app/permanent

CMD ["python", "server.py"]
