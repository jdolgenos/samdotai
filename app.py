from flask import Flask, render_template, request, jsonify, session
import requests
import json
import time
import pandas as pd
import re
from typing import Any, Dict, Tuple, List, Optional
import os
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'

# Box OAuth Configuration (from your existing app)
BOX_CLIENT_ID = "k5nioqr05lsa3z2l2ba0wy3q2yg97pc2"
BOX_CLIENT_SECRET = "lmEgU3H449ZOiTxyRbjXZe1iut0E8InY"
BOX_REDIRECT_URI = "http://localhost:5000/oauth/callback"

# Box Enterprise Configuration (from the agent script)
BOX_ENTERPRISE_CLIENT_ID = "ubqy5t192g86y3nxm82jouf97j2lf3r1"
BOX_ENTERPRISE_CLIENT_SECRET = "AjZxxeSduFKEXrgRfXMI5LkfcftyxRbI"
BOX_ENTERPRISE_ID = "211757737"

BOX_API_ROOT = "https://api.box.com"
_TOKEN_CACHE = {"token": None, "exp": 0}

def get_enterprise_token(force: bool = False) -> str:
    """
    Return a valid enterprise-level CCG token.
    Refresh only when it is missing or about to expire (<60 s left).
    """
    if not force and _TOKEN_CACHE["token"] and time.time() < _TOKEN_CACHE["exp"] - 60:
        return _TOKEN_CACHE["token"]

    resp = requests.post(
        "https://api.box.com/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": BOX_ENTERPRISE_CLIENT_ID,
            "client_secret": BOX_ENTERPRISE_CLIENT_SECRET,
            "box_subject_type": "enterprise",
            "box_subject_id": BOX_ENTERPRISE_ID,
        },
    )

    try:
        resp.raise_for_status()
        payload = resp.json()
    except Exception as e:
        raise RuntimeError(f"OAuth failure: {resp.status_code} - {resp.text}") from e

    token = payload.get("access_token")
    expiry = payload.get("expires_in", 3600)

    if not token:
        raise RuntimeError(f"OAuth response missing token: {json.dumps(payload)}")

    _TOKEN_CACHE.update(token=token, exp=time.time() + expiry)
    return token

def get_user_access_token() -> Optional[str]:
    """Get the user's access token from session"""
    return session.get('access_token')

def refresh_user_token() -> Optional[str]:
    """Refresh the user's access token using the refresh token"""
    refresh_token = session.get('refresh_token')
    if not refresh_token:
        return None
    
    resp = requests.post(
        "https://api.box.com/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": BOX_CLIENT_ID,
            "client_secret": BOX_CLIENT_SECRET,
        },
    )
    
    if resp.status_code == 200:
        tokens = resp.json()
        session['access_token'] = tokens['access_token']
        session['refresh_token'] = tokens['refresh_token']
        return tokens['access_token']
    
    return None

def validate_user_token() -> Optional[str]:
    """Validate user token and refresh if needed"""
    print("DEBUG: validate_user_token() called")
    access_token = get_user_access_token()
    print(f"DEBUG: access_token from session: {access_token[:10] if access_token else 'None'}...")
    if not access_token:
        print("DEBUG: No access token in session")
        return None
    
    # Test token validity
    print("DEBUG: Testing token validity with /users/me")
    resp = requests.get(
        'https://api.box.com/2.0/users/me',
        headers={'Authorization': f'Bearer {access_token}'}
    )
    print(f"DEBUG: /users/me response status: {resp.status_code}")
    
    if resp.status_code == 200:
        print("DEBUG: Token is valid, returning it")
        return access_token
    elif resp.status_code == 401:
        print("DEBUG: Token expired, trying to refresh")
        # Try to refresh
        refreshed_token = refresh_user_token()
        print(f"DEBUG: Refreshed token: {refreshed_token[:10] if refreshed_token else 'None'}...")
        return refreshed_token
    
    print(f"DEBUG: Unexpected response status {resp.status_code}, returning None")
    return None

def box_ai_text_gen(prompt: str, dialogue_history: list = [], agent_id: str = "26207278", tries: int = 2, user_token: str = None) -> dict:
    """Box AI text generation using user token or enterprise token as fallback"""
    file_data = [{"type": "file", "id": "1897961991698", "content": ""}]

    for attempt in range(tries):
        # Use user token if provided, otherwise fall back to enterprise token
        if user_token:
            token = user_token
        else:
            token = get_enterprise_token(force=(attempt == 1))
            
        resp = requests.post(
            "https://api.box.com/2.0/ai/text_gen",
            headers={"Authorization": f"Bearer {token}",
                     "Content-Type": "application/json"},
            data=json.dumps({
                "prompt": prompt,
                "items": file_data,
                "dialogue_history": dialogue_history,
                "ai_agent": {"type": "ai_agent_id", "id": agent_id},
            }),
        )

        if resp.status_code != 401:
            resp.raise_for_status()
            return resp.json()

    raise RuntimeError("Auth failed twice; check client_id/secret or rate limit")

# Multi-purpose endpoint definitions (from the agent script)
_ENDPOINTS: Dict[Tuple[str, str], Dict[str, Any]] = {
    ("folders", "create"): {
        "method": "POST",
        "path": "/2.0/folders",
        "ctype": "application/json"
    },
    ("folders", "copy"): {
        "method": "POST",
        "path": "/2.0/folders/{folder_id}/copy",
        "ctype": "application/json"
    },
    ("files", "copy"): {
        "method": "POST",
        "path": "/2.0/files/{file_id}/copy",
        "ctype": "application/json"
    },
    ("docgen", "generate"): {
        "method": "POST",
        "path": "/2.0/docgen_batches",
        "ctype": "application/json"
    },
    ("metadata_template", "create"): {
        "method": "POST",
        "path": "/2.0/metadata_templates/schema",
        "ctype": "application/json"
    },
}

def box_request(op_key: Tuple[str, str], path_vars: Dict[str, Any] | None = None, 
                body: Any | None = None, token: str | None = None) -> dict:
    """Generic Box API wrapper - now defaults to user token"""
    if op_key not in _ENDPOINTS:
        raise ValueError(f"Unknown operation {op_key}")

    spec = _ENDPOINTS[op_key]
    path = spec["path"].format(**(path_vars or {}))
    url = BOX_API_ROOT + path
    
    # Use provided token, or try user token first, then fall back to enterprise token
    if token:
        auth_token = token
    else:
        auth_token = validate_user_token()
        if not auth_token:
            auth_token = get_enterprise_token()
    
    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Content-Type": spec["ctype"]
    }

    data = None
    if body is not None:
        data = json.dumps(body)

    resp = requests.request(spec["method"], url, headers=headers, data=data)
    try:
        resp.raise_for_status()
    except requests.HTTPError as e:
        raise RuntimeError(f"{spec['method']} {url} -> {resp.status_code}: {resp.text}") from e

    return resp.json() if resp.content else {}

def actions_from_text(text: str) -> pd.DataFrame:
    """Extract <action>…</action> blocks and return one row per action"""
    blocks = re.findall(r"<action>(.*?)</action>", text, flags=re.DOTALL)
    actions: List[Dict[str, Any]] = []

    for raw in blocks:
        try:
            parsed = json.loads(raw.strip())
            if isinstance(parsed, list):
                actions.extend(parsed)
            else:
                actions.append(parsed)
        except json.JSONDecodeError:
            continue

    return pd.DataFrame(actions)

def run_action_plan(df: pd.DataFrame, token: Optional[str] = None) -> pd.DataFrame:
    """Execute action plan with Box API calls"""
    df = df.copy()
    df["api_response"] = None

    for idx, row in df.iterrows():
        try:
            op = (row["resource"], row["action"])
            if op in _ENDPOINTS:
                resp = box_request(op, 
                                 path_vars=row.get("path_vars", {}),
                                 body=row.get("body"),
                                 token=token)
                df.at[idx, "api_response"] = resp
            else:
                df.at[idx, "api_response"] = {"error": f"Unknown operation: {op}"}
        except Exception as e:
            df.at[idx, "api_response"] = {"error": str(e)}

    return df

@app.route('/api/ai-agents')
def get_ai_agents():
    """Fetch available AI agents using user token with text_gen mode"""
    user_token = validate_user_token()
    if not user_token:
        print("DEBUG: No user token available")
        return jsonify({"error": "Authentication required"}), 401
    
    try:
        print(f"DEBUG: Making request to Box AI agents API with mode=text_gen")
        resp = requests.get(
            "https://api.box.com/2.0/ai_agents",
            headers={"Authorization": f"Bearer {user_token}"},
            params={"mode": "text_gen"}
        )
        print(f"DEBUG: Response status: {resp.status_code}")
        resp.raise_for_status()
        data = resp.json()
        print(f"DEBUG: Raw response data: {json.dumps(data, indent=2)}")
        
        # Since we're using mode=text_gen, all returned agents should have text_gen capabilities
        # We just need to filter by access_state: "enabled"
        filtered_agents = []
        total_agents = len(data.get('entries', []))
        print(f"DEBUG: Total text_gen agents returned: {total_agents}")
        
        for i, agent in enumerate(data.get('entries', [])):
            print(f"DEBUG: Agent {i+1} - ID: {agent.get('id')}, Name: {agent.get('name')}")
            print(f"DEBUG: Agent {i+1} - access_state: {agent.get('access_state')}")
            
            if agent.get('access_state') == 'enabled':
                filtered_agents.append({
                    'id': agent['id'],
                    'name': agent['name'],
                    'description': agent.get('text_gen', {}).get('description', ''),
                    'icon_reference': agent.get('icon_reference', '')
                })
                print(f"DEBUG: Agent {i+1} - INCLUDED in filtered list")
            else:
                print(f"DEBUG: Agent {i+1} - EXCLUDED (not enabled)")
        
        print(f"DEBUG: Final filtered agents count: {len(filtered_agents)}")
        return jsonify({"agents": filtered_agents})
    
    except Exception as e:
        print(f"DEBUG: Exception in get_ai_agents: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/')
def index():
    """Main page - either show OAuth or chat interface"""
    access_token = validate_user_token()
    if access_token:
        return render_template('chat.html')
    else:
        return render_template('oauth.html', 
                             client_id=BOX_CLIENT_ID,
                             redirect_uri=BOX_REDIRECT_URI)

@app.route('/oauth/callback')
def oauth_callback():
    """Handle OAuth callback"""
    code = request.args.get('code')
    if not code:
        return "OAuth failed: No code received", 400
    
    # Exchange code for tokens
    resp = requests.post(
        "https://api.box.com/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "client_id": BOX_CLIENT_ID,
            "client_secret": BOX_CLIENT_SECRET,
            "redirect_uri": BOX_REDIRECT_URI,
        },
    )
    
    if resp.status_code != 200:
        return f"Token exchange failed: {resp.text}", 400
    
    tokens = resp.json()
    session['access_token'] = tokens['access_token']
    session['refresh_token'] = tokens['refresh_token']
    
    return render_template('chat.html')

@app.route('/api/chat', methods=['POST'])
def chat():
    """Chat endpoint for agentic conversation"""
    # Validate user authentication
    print("DEBUG: Starting chat endpoint")
    print(f"DEBUG: Session contents: {dict(session)}")
    user_token = validate_user_token()
    print(f"DEBUG: User token from validate_user_token: {user_token[:10] if user_token else 'None'}...")
    if not user_token:
        print("DEBUG: No valid user token, returning 401")
        return jsonify({"error": "Authentication required"}), 401
    
    data = request.json
    user_message = data.get('message', '')
    conversation_history = data.get('history', [])
    agent_id = data.get('agent_id', '26207278')  # Use selected agent ID or default
    
    if not user_message:
        return jsonify({"error": "Message is required"}), 400
    
    try:
        # Get AI response using user token and selected agent
        agent_response = box_ai_text_gen(
            user_message, 
            dialogue_history=conversation_history, 
            agent_id=agent_id,
            user_token=user_token
        )
        
        response_data = {
            "message": agent_response['answer'],
            "created_at": agent_response.get('created_at', datetime.now().isoformat()),
            "has_actions": "<action>" in agent_response['answer']
        }
        
        # If response contains actions, validate and prepare execution
        if response_data["has_actions"]:
            validation_response = box_ai_text_gen(
                agent_response['answer'], 
                agent_id='26559855',
                user_token=user_token
            )
            action_df = actions_from_text(validation_response['answer'])
            
            if not action_df.empty:
                response_data["action_plan"] = action_df.to_dict('records')
        
        return jsonify(response_data)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/execute-actions', methods=['POST'])
def execute_actions():
    """Execute action plan and get agent response"""
    user_token = validate_user_token()
    if not user_token:
        return jsonify({"error": "Authentication required"}), 401
    
    data = request.json
    actions = data.get('actions', [])
    agent_id = data.get('agent_id', '26207278')  # Default agent if not provided
    
    if not actions:
        return jsonify({"error": "No actions provided"}), 400
    
    try:
        action_df = pd.DataFrame(actions)
        # Use user token for operations now
        results_df = run_action_plan(action_df, token=user_token)
        results = results_df.to_dict('records')
        
        # Create a summary of the action results for the agent
        successful_actions = []
        failed_actions = []
        
        for result in results:
            action_summary = f"{result.get('resource', 'unknown')}: {result.get('action', 'unknown')}"
            if result.get('api_response') and not result['api_response'].get('error'):
                successful_actions.append({
                    'action': action_summary,
                    'details': result['api_response']
                })
            else:
                failed_actions.append({
                    'action': action_summary,
                    'error': result.get('api_response', {}).get('error', 'Unknown error')
                })
        
        # Create a summary message for the agent
        summary_parts = []
        if successful_actions:
            summary_parts.append(f"Successfully completed {len(successful_actions)} actions:")
            for action in successful_actions:
                summary_parts.append(f"- {action['action']}")
                # Include key details like IDs for new objects
                if 'id' in action['details']:
                    summary_parts.append(f"  Created with ID: {action['details']['id']}")
        
        if failed_actions:
            summary_parts.append(f"Failed {len(failed_actions)} actions:")
            for action in failed_actions:
                summary_parts.append(f"- {action['action']}: {action['error']}")
        
        action_summary = "\n".join(summary_parts)
        
        # Get agent response to the action results
        try:
            agent_response = box_ai_text_gen(
                prompt=f"The following actions have been executed:\n\n{action_summary}\n\nPlease provide a brief summary of what was accomplished.",
                agent_id=agent_id,
                user_token=user_token
            )
            
            return jsonify({
                "results": results,
                "success": True,
                "agent_response": {
                    "message": agent_response['answer'],
                    "created_at": agent_response.get('created_at', datetime.now().isoformat())
                }
            })
        
        except Exception as agent_error:
            print(f"DEBUG: Error getting agent response: {str(agent_error)}")
            # Return results even if agent response fails
            return jsonify({
                "results": results,
                "success": True
            })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/api/box-operation', methods=['POST'])
def box_operation():
    """Generic Box API operation endpoint"""
    user_token = validate_user_token()
    if not user_token:
        return jsonify({"error": "Authentication required"}), 401
    
    data = request.json
    operation = data.get('operation')  # tuple like ("folders", "create")
    path_vars = data.get('path_vars', {})
    body = data.get('body')
    
    try:
        # Use user token for operations now
        result = box_request(tuple(operation), path_vars=path_vars, body=body, token=user_token)
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/logout')
def logout():
    """Logout and clear session"""
    session.clear()
    return render_template('oauth.html', 
                         client_id=BOX_CLIENT_ID,
                         redirect_uri=BOX_REDIRECT_URI)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000) 