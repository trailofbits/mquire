#!/usr/bin/env python3

from flask import Flask, render_template_string, request
import subprocess
import re
import sys
import shutil
import webbrowser

app = Flask(__name__)

template = """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>mquire-webui</title>
  <script>
    function toggleDarkMode() {
      document.body.classList.toggle('light-mode');
    }
  </script>
  <style>
    body {
      background-color: #121212;
      color: white;
      font-family: monospace;
      text-align: center;
    }
    .light-mode {
      background-color: white;
      color: black;
    }
    textarea {
      width: 60%;
      height: 100px;
      background-color: #121212;
      color: white;
      border: 1px solid white;
    }
    .light-mode textarea {
      background-color: white;
      color: black;
      border: 1px solid black;
    }
    table {
      margin: 20px auto;
      border-collapse: collapse;
      width: 80%;
    }
    th, td {
      border: 1px solid white;
      padding: 8px;
    }
    .light-mode th, .light-mode td {
      border-color: black;
      color: black;
    }
    button {
      margin-top: 10px;
      padding: 10px;
      cursor: pointer;
    }
    #stderr-box {
      margin: 20px auto;
      padding: 10px;
      border: 1px solid white;
      width: 60%;
    }
    .light-mode #stderr-box {
      border-color: black;
    }
  </style>
</head>
<body>
  <button style="position: absolute; top: 10px; right: 10px;" onclick="toggleDarkMode()">Toggle Dark Mode</button>
  <h1>mquire-webui</h1>
  <form method="post">
    <textarea name="query" placeholder="Enter SQL query here...">{{ query }}</textarea><br />
    <button type="submit">Run</button>
  </form>
  
  {% if stderr_output %}
  <div id="stderr-box">{{ stderr_output }}</div>
  {% endif %}
  
  {% if table_data %}
  <table>
    <thead>
      <tr>
        {% for col in table_data[0].keys() %}
        <th>{{ col }}</th>
        {% endfor %}
      </tr>
    </thead>
    <tbody>
      {% for row in table_data %}
      <tr>
        {% for value in row.values() %}
        <td>{{ value }}</td>
        {% endfor %}
      </tr>
      {% endfor %}
    </tbody>
  </table>
  {% endif %}
</body>
</html>
"""


@app.route("/", methods=["GET", "POST"])
def index():
    query = ""
    stdout_output = ""
    stderr_output = ""
    table_data = []

    if request.method == "POST":
        query = request.form.get("query", "").strip()
        if query:
            try:
                image_path = sys.argv[1]
                result = subprocess.run(
                    ["mq", image_path, query], capture_output=True, text=True
                )

                stdout_output = result.stdout.strip()
                stderr_output = result.stderr.strip()

                if stdout_output:
                    rows = stdout_output.split("\n")
                    table_data = []
                    for row in rows:
                        matches = re.findall(r'(\w+):"(.*?)"', row)
                        if matches:
                            table_data.append({key: value for key, value in matches})
            except Exception as e:
                stdout_output = str(e)

    return render_template_string(
        template,
        query=query,
        stdout_output=stdout_output,
        stderr_output=stderr_output,
        table_data=table_data,
    )


if __name__ == "__main__":
    if len(sys.argv) < 2:
        raise ValueError("Usage: python3 webui.py <path to .raw file>")

    if shutil.which("mq") is None:
        raise Exception("'mq' command not found in PATH")

    webbrowser.open("http://127.0.0.1:5000/")
    app.run(debug=False)
