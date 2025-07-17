# Box Agent Chat - Flask App

A Flask-based agentic conversation app that combines OAuth authentication with Box AI capabilities. This app allows users to chat with AI agents to perform various Box operations through natural language conversation.

## Features

- **OAuth Authentication**: Secure user authentication using Box OAuth 2.0
- **Token Management**: Automatic token refresh using the same logic as your original app
- **Agentic Conversation**: Chat with AI agents powered by Box AI
- **Action Execution**: AI can generate and execute Box API actions
- **Multi-purpose Endpoint**: Generic Box API wrapper for various operations
- **Modern UI**: Clean, responsive chat interface

## Architecture

- **Frontend**: HTML/CSS/JavaScript chat interface
- **Backend**: Python Flask server
- **Authentication**: Box OAuth 2.0 for user tokens + CCG for enterprise operations
- **AI**: Box AI text generation with custom agents

## Setup Instructions

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Configuration

The app uses the same OAuth credentials from your existing app and enterprise credentials from the Box agent script. Update the following in `app.py` if needed:

```python
# User OAuth (from your existing app)
BOX_CLIENT_ID = "k5nioqr05lsa3z2l2ba0wy3q2yg97pc2"
BOX_CLIENT_SECRET = "lmEgU3H449ZOiTxyRbjXZe1iut0E8InY"

# Enterprise CCG (from agent script)
BOX_ENTERPRISE_CLIENT_ID = "ubqy5t192g86y3nxm82jouf97j2lf3r1"
BOX_ENTERPRISE_CLIENT_SECRET = "AjZxxeSduFKEXrgRfXMI5LkfcftyxRbI"
BOX_ENTERPRISE_ID = "211757737"
```

### 3. Update Box App Configuration

In your Box Developer Console:
1. Go to your OAuth app settings
2. Add `http://localhost:5000/oauth/callback` to the Redirect URIs
3. Ensure the app has the necessary scopes for your use case

### 4. Run the Application

```bash
python app.py
```

The app will be available at `http://localhost:5000`

## Usage

### 1. Authentication
- Navigate to `http://localhost:5000`
- Click "Sign in with Box" to authenticate
- Complete the OAuth flow
- You'll be redirected to the chat interface

### 2. Chat Interface
- Type natural language requests about Box operations
- Examples:
  - "Create a new folder called 'Project Files'"
  - "Copy file ID 123456 to folder ID 789"
  - "Generate a document using template ID 456"
  - "Show me metadata templates"

### 3. Action Execution
- When the AI generates actions, they'll appear in yellow action panels
- Click "Execute Actions" to run the Box API operations
- Results will be displayed in blue result panels

## API Endpoints

### Frontend Routes
- `GET /` - Main page (OAuth or chat interface)
- `GET /oauth/callback` - OAuth callback handler
- `GET /logout` - Logout and clear session

### API Routes
- `POST /api/chat` - Send chat message to AI agent
- `POST /api/execute-actions` - Execute action plan
- `POST /api/box-operation` - Generic Box API operation

## Supported Box Operations

The multi-purpose endpoint supports these operations:

- **Folders**: create, copy, move
- **Files**: copy, move
- **Document Generation**: generate documents from templates
- **Metadata Templates**: create, update
- **Metadata**: create/update on folders and files
- **Users**: create, update
- **Collaborations**: create

## AI Agents

The app uses Box AI agents for different purposes:
- **Main Agent** (ID: 26207278): General conversation and operation planning
- **Validation Agent** (ID: 26559855): Validates and structures action plans

## Token Management

The app implements robust token management:
- **User Tokens**: OAuth tokens stored in Flask session with automatic refresh
- **Enterprise Tokens**: CCG tokens cached and refreshed as needed
- **Validation**: Automatic token validation and refresh before API calls

## Security Considerations

- Change the Flask secret key in production
- Store sensitive credentials in environment variables
- Use HTTPS in production
- Implement proper session management for production use

## Troubleshooting

### Common Issues

1. **Import Errors**: Make sure all dependencies are installed via `pip install -r requirements.txt`

2. **OAuth Failures**: Verify the redirect URI is correctly configured in Box Developer Console

3. **Token Issues**: Check that your Box app has the correct scopes and permissions

4. **AI Agent Errors**: Ensure the agent IDs exist and are accessible with your enterprise credentials

### Debug Mode

The app runs in debug mode by default. For production:

```python
if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
```

## Development

### Project Structure
```
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── templates/
│   ├── oauth.html        # OAuth login page
│   └── chat.html         # Chat interface
└── README.md             # This file
```

### Adding New Operations

To add new Box operations:

1. Add the endpoint definition to `_ENDPOINTS` in `app.py`
2. The operation will automatically be available through the generic API

### Customizing AI Behavior

- Modify agent IDs to use different Box AI agents
- Adjust prompts and conversation history handling
- Add custom action validation logic

## Integration with Original App

This Flask app is designed to work alongside your existing document generation SPA:

- **Same OAuth Setup**: Uses the same Box OAuth credentials
- **Token Compatibility**: Tokens can be shared between applications
- **Similar Architecture**: Follows the same authentication patterns

You can run both applications simultaneously or migrate users between them as needed. 