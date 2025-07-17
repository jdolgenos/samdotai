// Globals
let fileId = null;
const clientId = "k5nioqr05lsa3z2l2ba0wy3q2yg97pc2";
const clientSecret = "lmEgU3H449ZOiTxyRbjXZe1iut0E8InY";
const redirectUri = "https://jdolgenos.github.io/doc-genie/index.html";
const authUrl = `https://account.box.com/api/oauth2/authorize?response_type=code&client_id=${clientId}&redirect_uri=${encodeURIComponent(redirectUri)}`;


// Exchange auth code for token
async function getAccessToken(code) {
    const url = "https://api.box.com/oauth2/token";
    const body = new URLSearchParams({
        grant_type: "authorization_code",
        code,
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uri: redirectUri,
    });

    const response = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
    });

    console.log("Token exchange complete");

    if (!response.ok) {
        const errorText = await response.text();
        console.error(`Failed to get access token: ${errorText}`);
        throw new Error(`Failed to get access token: ${response.statusText}`);
    }

    const data = await response.json();
    console.log("Token exchange complete");

    return data;
}

// Save tokens to session storage
function saveTokens(accessToken, refreshToken) {
    sessionStorage.setItem("access_token", accessToken);
    sessionStorage.setItem("refresh_token", refreshToken);
}

// Retrieve tokens
function getTokens() {
    return {
        accessToken: sessionStorage.getItem("access_token"),
        refreshToken: sessionStorage.getItem("refresh_token"),
    };
}

// Clear tokens
function clearTokens() {
    sessionStorage.removeItem("access_token");
    sessionStorage.removeItem("refresh_token");
}

// Extract URL parameters
function getUrlParameter(name) {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get(name);
}

// Handle OAuth Redirect and Token Exchange
async function handleOAuthRedirect() {
    const code = getUrlParameter('code');
    if (code) {
        try {
            console.log('OAuth code detected. Exchanging for tokens...');
            const tokenResponse = await getAccessToken(code);
            console.log("Token exchange complete");
            saveTokens(tokenResponse.access_token, tokenResponse.refresh_token);
            console.log('Tokens saved successfully.');

            // Remove the `code` from the URL
            window.history.replaceState({}, document.title, window.location.pathname);

            return true; // Code processed successfully
        } catch (error) {
            console.error('Failed to handle OAuth redirect:', error);
            alert('An error occurred during authentication. Please try again.');
        }
    }
    return false; // No code to process
}

// Simple callout to validate the token
async function validateToken(token) {
    const response = await fetch('https://api.box.com/2.0/users/me', {
        headers: { Authorization: `Bearer ${token}` },
    });

    if (!response.ok) {
        throw new Error('Token is invalid or expired.');
    }
    return true; // Token is valid
}

// Validate and Get Access Token
async function getValidAccessToken() {
    const { accessToken, refreshToken } = getTokens();

    // Step 1: Check if an access token is available and test its validity
    if (accessToken) {
        try {
            console.log('Validating access token...');
            await validateToken(accessToken); // Make an API call to validate
            console.log('Access token is valid.');
            return accessToken;
        } catch (error) {
            console.error('Access token is invalid or expired:', error);
            clearTokens(); // Clear invalid tokens
        }
    }

    // Step 2: Attempt to refresh the token if a refresh token is available
    if (refreshToken) {
        try {
            console.log('Refreshing access token...');
            const newAccessToken = await refreshTokens(refreshToken);
            console.log('Access token refreshed successfully.');
            return newAccessToken;
        } catch (error) {
            console.error('Failed to refresh tokens:', error);
            clearTokens(); // Clear invalid tokens
        }
    }

    // Step 3: Redirect to OAuth flow if no valid tokens are available
    console.log('Redirecting to OAuth...');
    window.location.href = authUrl;
    return null; // Return null since user will be redirected
}

// Initialize File Picker with Token
async function initializeFilePicker(accessToken) {
    if (!accessToken) {
        console.error('Access token not available. File picker cannot be initialized.');
        return;
    }

    const filePicker = new Box.FilePicker();
    updateInstructions(1);

    filePicker.show('0', accessToken, {
        container: '#filePickerContainer',
        chooseButtonLabel: 'Select Template',
        cancelButtonLabel: 'Cancel',
        maxSelectable: 1,
        extensions: ['doc', 'docx'],
        canUpload: false,
        canSetShareAccess: false,
        canCreateNewFolder: false,
        autoFocus: true,
        logoUrl: 'logo.png',
    });

    filePicker.addListener('choose', async function (items) {
        if (!items || items.length === 0) {
            alert('No file selected.');
            return;
        }

        const selectedFileId = items[0]?.id;
        const isValidTemplate = await validateTemplate(selectedFileId);

        if (!isValidTemplate) {
            alert('Selected file is not a valid template.');
            return;
        }

        fileId = selectedFileId;

        // Hide file picker and show app content with the correct styles
        document.getElementById('filePickerContainer').style.display = 'none';
        const appContent = document.getElementById('appContent');
        appContent.style.display = 'block'; // Ensure it is displayed
        appContent.classList.add('visible'); // Optional, for additional styling
        appContent.style.display = 'flex'; // Ensure flexbox layout is applied

        console.log('File picker hidden, showing app content.');
        showPreview(fileId, accessToken);
        setupAppContentEventListeners();
        updateInstructions(2);
    });
}

document.addEventListener('DOMContentLoaded', async () => {
    try {
        // Handle OAuth Redirect
        const codeProcessed = await handleOAuthRedirect();

        if (!codeProcessed) {
            console.log('Checking for valid tokens...');
            const accessToken = await getValidAccessToken();
            if (accessToken) {
                console.log('Access token found. Initializing file picker...');
                await initializeFilePicker(accessToken);
            } else {
                console.log('No valid tokens found. Redirecting to OAuth.');
                return; // The user is redirected to OAuth in `getValidAccessToken`
            }
        } else {
            console.log('OAuth code processed. Initializing file picker...');
            const accessToken = await getValidAccessToken();
            if (accessToken) {
                await initializeFilePicker(accessToken);
            }
        }
    } catch (error) {
        console.error('Error during initialization:', error);
        alert('An error occurred during initialization. Please try again.');
    }
});

// reset the event listeners after the second stage of the app is loaded
function setupAppContentEventListeners() {
    const downloadCsvButton = document.getElementById('downloadCsvButton');
    const uploadCsvButton = document.getElementById('uploadCsvButton');

    if (downloadCsvButton) {
        downloadCsvButton.addEventListener('click', handleDownloadCsv);
    }

    if (uploadCsvButton) {
        uploadCsvButton.addEventListener('click', handleUploadCsv);
    }
}

// Validate Template
async function validateTemplate(selectedFileId) {
    const templates = await fetchBoxApi('https://api.box.com/2.0/docgen_templates?limit=1000');
    return templates.entries.some((template) => template.file.id === selectedFileId);
}

// Initialize Box Client
function initializeClient(accessToken) {
    const { BoxClient, BoxDeveloperTokenAuth } = window['box-typescript-sdk-gen'];
    const client = new BoxClient({ auth: new BoxDeveloperTokenAuth({ accessToken }) });
    console.log('Box Client initialized with token');
}

// Show file preview
function showPreview(fileId, accessToken) {
    const preview = new Box.ContentPreview();
    preview.show(fileId, accessToken, {
        container: '.preview-container',
        showDownload: true,
    });
}

async function fetchBoxApi(url, method = 'GET', body = null) {
    const accessToken = await getValidAccessToken();
    const headers = {
        Authorization: `Bearer ${accessToken}`,
        'Content-Type': 'application/json',
    };
    const options = { method, headers };

    // Assign body directly if it's provided
    if (body) options.body = body; // No need to stringify here

    const response = await fetch(url, options);

    if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`API Error: ${response.statusText} - ${errorText}`);
    }
    return response.json();
}

// Get Text Representation
async function getTextRepresentation(fileId) {
    try {
        console.log('Fetching text representation...');
        const accessToken = await getValidAccessToken();
        const response = await fetch(`https://api.box.com/2.0/files/${fileId}?fields=representations`, {
            method: 'GET',
            headers: {
                Authorization: `Bearer ${accessToken}`,
                'x-rep-hints': '[extracted_text]',
            },
        });

        if (!response.ok) {
            throw new Error(`Failed to fetch representations: ${response.statusText}`);
        }

        const data = await response.json();
        const urlTemplate = data.representations?.entries[0]?.content?.url_template.replace('{+asset_path}', '');
        if (!urlTemplate) {
            throw new Error('No valid extracted text representation available.');
        }

        const textResponse = await fetch(urlTemplate, {
            method: 'GET',
            headers: { Authorization: `Bearer ${accessToken}` },
        });

        if (!textResponse.ok) {
            throw new Error(`Failed to fetch extracted text: ${textResponse.statusText}`);
        }

        return await textResponse.text();
    } catch (error) {
        console.error('Error in getTextRepresentation:', error);
        throw error;
    }
}

// Apply Metadata to a Folder
async function applyMetadataToFolder(folderId, templateKey, metadataJson) {
    try {
        const accessToken = await getValidAccessToken();
        const url = `https://api.box.com/2.0/folders/${folderId}/metadata/enterprise/${templateKey}`;
        const response = await fetch(url, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${accessToken}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify(metadataJson),
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Failed to apply metadata: ${errorText}`);
        }

        console.log(`Metadata applied successfully to folder ID: ${folderId}`);
    } catch (error) {
        console.error(`Error applying metadata to folder ID ${folderId}:`, error);
    }
}

// Create Cascade Policy for a Folder
async function createCascadePolicyForFolder(folderId, templateKey) {
    try {
        const accessToken = await getValidAccessToken();
        const url = "https://api.box.com/2.0/metadata_cascade_policies";
        const response = await fetch(url, {
            method: "POST",
            headers: {
                Authorization: `Bearer ${accessToken}`,
                "Content-Type": "application/json",
            },
            body: JSON.stringify({
                folder_id: folderId,
                scope: "enterprise",
                templateKey: templateKey,
            }),
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Failed to create cascade policy: ${errorText}`);
        }

        console.log(`Cascade policy created successfully for folder ID: ${folderId}`);
    } catch (error) {
        console.error(`Error creating cascade policy for folder ID ${folderId}:`, error);
    }
}

// Get Document Tags
async function getDocTags(fileId) {
    const textRepresentation = await getTextRepresentation(fileId);
    const matches = textRepresentation.match(/\{\{(.*?)\}\}/g) || [];
    return [...new Set(matches.map(tag => tag.replace(/\{\{|\}\}/g, '')))];
}

async function callAutogenerateRowsForColumn(columnName) {
    // Get a valid Box access token (or master token if available)
    const accessToken = await getValidAccessToken();

    // Set up the request headers
    const myHeaders = new Headers();
    myHeaders.append("Content-Type", "application/json");
    myHeaders.append("Authorization", `Bearer ${accessToken}`);
    // Include the cookie header if needed by your API; adjust values as necessary.
    myHeaders.append("Cookie", "box_visitor_id=647a31ad57b123.60665629; site_preference=desktop; csrf-token=nL5HJMWmJLSPTVC9LCfJ0r3g-s6fauOV9pctTAwL6EQ");

    // Build the prompt text using the column name
    const promptText = "You will be given the column name for a table you need to fill out. Fill in 10 rows of the column with random values based on the column name. So for example if the column name is -firstName, make sure the first value of each new row is a first name. If the column name is -phoneNumber, make sure the 10 rows have phone numbers in the format xxx-xxx-xxxx. If you are unsure about what value to use for one of the columns because the column name is not clear, then just use the value -NA. DO NOT RETURN ANYTHING EXCEPT THE FULL VALUES TO USE FOR THE COLUMN, INCLUDING THE COLUMN NAME. YOUR RESPONSE SHOULD INCLUDE 11 ROWS IN TOTAL WITH NO MISSING VALUES, OR TEXT IN FRONT OF OR FOLLOWING THE CSV DATA. DO NOT USE COMMAS FOR A SINGLE COLUMN VALUE. FOR EXAMPLE, WHEN CREATING ADDRESSES, USE THE FORMAT STREET CITY STATE ZIPCODE, NO COMMAS. Here are the values that start the csv:" + columnName;

    // Build the request body
    const body = JSON.stringify({
         "prompt": promptText,
         "items": [
             {
                "type": "file",
                "id": fileId,
                "content": ""
             }
         ],
         "dialogue_history": []
    });

    const requestOptions = {
         method: "POST",
         headers: myHeaders,
         body: body,
         redirect: "follow"
    };

    // Make the API call to the Box AI text_gen endpoint
    const response = await fetch("https://api.box.com/2.0/ai/text_gen", requestOptions);
    if (!response.ok) {
         const errorText = await response.text();
         throw new Error(`Box API error: ${errorText}`);
    }
    
    // Read the raw response text
    const responseText = await response.text();

    // Parse the response as JSON and extract the "answer" field
    let jsonResponse;
    try {
        jsonResponse = JSON.parse(responseText);
    } catch (error) {
        console.error("Error parsing JSON from response:", responseText);
        throw error;
    }
    
    const rawAnswer = jsonResponse.answer;
    // Clean the response using our CSV cleaning function
    const cleanedCsv = reformatAnswerToCsv(rawAnswer);
    return cleanedCsv;
}

async function generateColumnsCsv() {
  // Get the document tags (assumed to be an array of column names)
  const docTags = await getDocTags(fileId); // e.g., ["tenantName", "contractDate", "propertyAddress", ...]
  
  // For each column name, call the API to generate a CSV column.
  const columnPromises = docTags.map(tag => callAutogenerateRowsForColumn(tag));
  
  // Wait for all API calls to complete.
  const columnResults = await Promise.all(columnPromises);
  
  const expectedRows = 11;
  
  // Split each returned CSV string into an array of rows,
  // clean them up, and ensure exactly expectedRows per column.
  const columnsData = columnResults.map(colCsv => {
    // Split by newline, trim each row, and remove any blank rows.
    let rows = colCsv.split(/\r?\n/).map(row => row.trim()).filter(row => row !== "");
    
    // If there are more than expectedRows, take only the first expectedRows.
    if (rows.length > expectedRows) {
      rows = rows.slice(0, expectedRows);
    }
    // If there are fewer than expectedRows, pad with empty strings.
    else if (rows.length < expectedRows) {
      while (rows.length < expectedRows) {
        rows.push("");
      }
    }
    
    return rows;
  });
  
  // Combine rows from each column row by row.
  const finalRows = [];
  for (let i = 0; i < expectedRows; i++) {
    const rowCells = columnsData.map(col => col[i] || '');
    finalRows.push(rowCells.join(','));
  }
  
  // The final CSV string will have exactly expectedRows rows and as many columns as there are doc tags.
  // Also, trim any extra whitespace or newlines.
  const finalCsv = finalRows.join('\n').trim();
  return finalCsv;
}

function reformatAnswerToCsv(answer) {
    // Remove surrounding whitespace and triple backticks
    let content = answer.trim();
    if (content.startsWith("```")) {
      content = content.substring(3);
    }
    if (content.endsWith("```")) {
      content = content.substring(0, content.length - 3);
    }
    content = content.trim();
    
    // Split the content into lines (ignoring blank lines)
    const lines = content.split(/\r?\n/).filter(line => line.trim() !== "");
    
    // For each line, split into fields using tab delimiter (or two-or-more spaces if tabs are missing)
    const processedLines = lines.map(line => {
      let fields;
      if (line.indexOf('\t') !== -1) {
        fields = line.split('\t');
      } else {
        fields = line.split(/\s{2,}/);
      }
      // For each field, trim, collapse spaces, and remove any surrounding quotes
      fields = fields.map(field => {
        let cleaned = field.trim().replace(/\s+/g, ' ');
        cleaned = cleaned.replace(/^['"]+|['"]+$/g, '');
        return cleaned;
      });
      // Since we expect this call to return a single column, join the fields with nothing.
      return fields.join('');
    });
    
    // Join the processed lines with newline characters
    let finalCsv = processedLines.join('\n');
    
    // Remove any illegal characters.
    // Allowed characters: A-Z, a-z, 0-9, comma, forward slash, hyphen, period,
    // !, @, #, $, %, ^, &, *, (, ), {, }, [, ], |, ?, <, >, backtick, tilde, and whitespace.
    finalCsv = finalCsv.replace(/[^A-Za-z0-9,\/\-.!@#$%^&*(){}\[\]|?<>`~\s]/g, '');
    
    return finalCsv;
    }
  
  // Updated CSV download handler with per-column API calls

function downloadCsv(tags) {
  // Create a CSV string with the header row from the tags.
  const csvContent = tags.join(',') + '\n';
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const link = document.createElement('a');
  link.href = URL.createObjectURL(blob);
  link.download = 'template.csv';
  link.click();
}

async function handleDownloadCsv() {
    const spinner = document.getElementById('loadingSpinner');
    spinner.style.display = 'block';
  
    try {
        // Get the doc tags (each tag becomes a column header)
        const tags = await getDocTags(fileId);
        // Check if the "Autogenerate rows" checkbox is checked.
        const autoGenCheckbox = document.getElementById('autogenerateRowsCheckbox');
  
        if (autoGenCheckbox && autoGenCheckbox.checked) {
            // For each tag (column name), call the API to generate 21 rows for that column.
            const columnPromises = tags.map(tag => callAutogenerateRowsForColumn(tag));
            // Wait for all API calls to complete.
            const columnResults = await Promise.all(columnPromises);
  
            // Split each column CSV into an array of rows (expecting 21 rows per column)
            const expectedRows = 21;
            const columnsData = columnResults.map(colCsv => {
                // Each column is assumed to be returned as a CSV string (one value per line)
                return colCsv.split(/\r?\n/).map(row => row.trim());
            });
  
            // Optionally warn if any column doesn't have 21 rows.
            columnsData.forEach((col, idx) => {
                if (col.length !== expectedRows) {
                    console.warn(`Column "${tags[idx]}" expected ${expectedRows} rows but got ${col.length}`);
                }
            });
  
            // Combine the columns row by row into a final CSV.
            const finalRows = [];
            for (let i = 0; i < expectedRows; i++) {
                // For each row, take the i-th element from each column array.
                const rowCells = columnsData.map(col => col[i] || '');
                finalRows.push(rowCells.join(','));
            }
  
            // The final CSV string with 21 rows and as many columns as there are tags.
            const finalCsv = finalRows.join('\n');
            downloadCsvString(finalCsv);
        } else {
            // If autogenerate is not checked, simply download a CSV with just the header row.
            downloadCsv(tags);
        }
    } catch (error) {
        console.error('Error downloading CSV:', error);
        alert('Error downloading CSV.');
    } finally {
        spinner.style.display = 'none';
    }
}

// Clean and Process Cell Data
function cleanCellValue(value) {
    return value
        .replace(/[\r\n]/g, '') // Remove carriage returns and newlines
        .replace(/,/g, '&#44;') // Replace commas with a safe alternative
        .trim(); // Remove extra whitespace
}

// Convert text to CamelCase
function camelCase(str) {
    return str
        .replace(/[^a-zA-Z0-9]/g, " ") // Remove non-alphanumeric characters
        .split(" ")
        .map((word, index) => 
            index === 0 
                ? word.toLowerCase() 
                : word.charAt(0).toUpperCase() + word.slice(1).toLowerCase()
        )
        .join("");
}

function downloadCsvString(csvContent) {
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = 'template.csv';
    link.click();
    updateInstructions(3);
}

// Parse CSV and handle quoted fields
function parseCsv(text) {
  // First, trim the text to remove any extra newlines/whitespace at the beginning or end.
  const trimmed = text.trim();
  // Split the text on newline characters and filter out any empty lines.
  return trimmed.split('\n')
                .filter(line => line.trim() !== "")
                .map(line => line.split(',').map(cell => cell.trim()));
}

// Handle Upload CSV
async function handleUploadCsv() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.csv';

    input.addEventListener('change', async (event) => {
        const file = event.target.files[0];
        if (!file) {
            alert('No file selected.');
            return;
        }

        const spinner = document.getElementById('loadingSpinner');
        spinner.style.display = 'block';

        try {
            const fileInfoResponse = await fetchBoxApi(`https://api.box.com/2.0/files/${fileId}?fields=parent`);
            const parentFolderId = fileInfoResponse.parent.id;

            const templatesFolderId = await checkOrCreateTemplatesFolder(parentFolderId);
            const uploadedFileId = await uploadCsvFile(templatesFolderId, file);
            let textRepresentation = await getTextRepresentation(uploadedFileId);
            
            // Clean up the CSV text: trim extra whitespace/newlines
            textRepresentation = textRepresentation.trim();
            
            // Remove extra empty rows:
            // Split the CSV text into lines, then filter out any line that becomes empty 
            // after removing commas, spaces, and tabs.
            let rows = textRepresentation.split(/\r?\n/);
            rows = rows.filter(row => row.replace(/[, \t]+/g, '').length > 0);
            textRepresentation = rows.join('\n');

            console.log("Cleaned CSV text:", textRepresentation);

            // Wrap table display in try/catch to handle potential parsing issues.
            try {
                displayCsvAsTable(textRepresentation);
            } catch (parseError) {
                console.error("Error displaying CSV as table:", parseError);
                alert("There was an error parsing the CSV. Please check the CSV format.");
                return;
            }

            appendMetadataDropdown(); // Updated function to include the checkbox
            updateInstructions(4);
        } catch (error) {
            console.error('Error handling CSV upload:', error);
            alert('An error occurred while processing the CSV.');
        } finally {
            spinner.style.display = 'none';
        }
    });

    input.click();
}

// Create Metadata Template from Tags
async function createMetadataTemplateFromTags(templateName) {
    const accessToken = await getValidAccessToken();
    try {
        const tableRows = document.querySelectorAll('#tableContainer table tr');
        const headers = Array.from(tableRows[0].querySelectorAll('th, td')).map(cell => cell.textContent.trim());

        // Build metadata template fields
        const fields = headers.map(header => ({
            type: 'string',
            key: header.replace(/\s+/g, '').replace(/[^a-zA-Z0-9]/g, '').toLowerCase(),
            displayName: header.replace(/[^a-zA-Z0-9]/g, ' '),
            description: '',
            hidden: false,
        }));

        // Construct payload
        const raw = JSON.stringify({
            scope: 'enterprise',
            templateKey: templateName.replace(/\s+/g, '').toLowerCase(),
            displayName: templateName,
            hidden: false,
            fields: fields,
            copyInstanceOnItemCopy: true,
        });

        // Make API call
        const requestOptions = {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${accessToken}`,
            },
            body: raw,
        };

        const response = await fetch('https://api.box.com/2.0/metadata_templates/schema', requestOptions);
        if (!response.ok) {
            throw new Error(`Failed to create metadata template: ${await response.text()}`);
        }

        //console.log(`Metadata template "${templateName}" created successfully.`);
        alert(`Metadata template "${templateName}" created successfully.`);
    } catch (error) {
        console.error('Error creating metadata template:', error);
        alert(`Error creating metadata template: ${error.message}`);
    }
}


function appendMetadataDropdown() {
    const tableContainer = document.getElementById('tableContainer');

    // Remove existing dropdown and checkbox if they exist
    const existingDropdown = document.getElementById('metadataTemplateDropdown');
    if (existingDropdown) existingDropdown.remove();

    const existingCheckboxContainer = document.getElementById('keywordCheckboxContainer');
    if (existingCheckboxContainer) existingCheckboxContainer.remove();

    // Create a container for the dropdown and checkbox
    const dropdownContainer = document.createElement('div');
    dropdownContainer.id = 'dropdownContainer';
    dropdownContainer.style.marginTop = '20px';
    dropdownContainer.style.display = 'flex';
    dropdownContainer.style.flexDirection = 'column';

    // Create the metadata dropdown
    const dropdown = document.createElement('select');
    dropdown.id = 'metadataTemplateDropdown';
    dropdown.style.width = '100%';
    dropdown.style.padding = '8px';
    dropdown.style.marginBottom = '10px';
    dropdown.innerHTML = `
        <option value="none">Do Not Add Metadata</option>
        <option value="create_new_template">Create Metadata Template from Tags</option>
    `;

    // Append the dropdown to the dropdown container
    dropdownContainer.appendChild(dropdown);

    // Create the checkbox container
    const checkboxContainer = document.createElement('div');
    checkboxContainer.id = 'keywordCheckboxContainer';
    checkboxContainer.style.display = 'flex';
    checkboxContainer.style.alignItems = 'center';
    checkboxContainer.style.marginTop = '10px';

    // Create the checkbox
    const keywordCheckbox = document.createElement('input');
    keywordCheckbox.type = 'checkbox';
    keywordCheckbox.id = 'keywordCheckbox';
    keywordCheckbox.style.marginRight = '8px';

    // Create the label for the checkbox
    const checkboxLabel = document.createElement('label');
    checkboxLabel.htmlFor = 'keywordCheckbox';
    checkboxLabel.textContent = 'Keyword to Format';

    // Append the checkbox and label to the checkbox container
    checkboxContainer.appendChild(keywordCheckbox);
    checkboxContainer.appendChild(checkboxLabel);

    // Append the checkbox container to the dropdown container
    dropdownContainer.appendChild(checkboxContainer);

    // Append the dropdown container to the table container
    tableContainer.appendChild(dropdownContainer);

    // Fetch existing metadata templates and add them as options
    getAllMetadataTemplates()
        .then((templates) => {
            templates.forEach((template) => {
                const option = document.createElement('option');
                option.value = template.templateKey;
                option.textContent = template.displayName;
                dropdown.appendChild(option);
            });
        })
        .catch((error) => console.error('Error fetching metadata templates:', error));
}

// process the json data if there are nested values included
function createNestedJson(data) {
    const result = {};
    for (const [key, value] of Object.entries(data)) {
        const keys = key.split('.');
        keys.reduce((acc, part, index) => {
            if (index === keys.length - 1) {
                acc[part] = value; // Assign the value to the last key
            } else {
                acc[part] = acc[part] || {}; // Create nested object if not exists
            }
            return acc[part];
        }, result);
    }
    return result;
}

// we have to handle the fact that metadata templates can use periods in display names but don't store them in keys
function sanitizeColumnName(columnName) {
    if (columnName.includes('.')) {
        // Remove periods, convert to lowercase, and remove spaces
        return columnName.replace(/\./g, '').replace(/\s+/g, '').toLowerCase();
    }
    // Return the column name as is if no periods
    return columnName;
}

// This function is to parse date strings to convert them to the correct date format
function parseRawDate(rawDate) {
    if (!rawDate) return null;

    // First try creating a native Date object directly
    const nativeDate = new Date(rawDate);
    if (!isNaN(nativeDate.getTime())) {
        return nativeDate;
    }

    // If the native Date parsing fails, handle specific known formats
    const [month, day, year] = rawDate.split(/[/-]/); // Support "/" or "-" as delimiters
    if (month && day && year) {
        const formattedDate = `${year.length === 2 ? "20" + year : year}-${month.padStart(2, "0")}-${day.padStart(
            2,
            "0"
        )}`;
        const correctedDate = new Date(formattedDate);
        if (!isNaN(correctedDate.getTime())) {
            return correctedDate;
        }
    }

    // Return null if all parsing attempts fail
    return null;
}

// Generate documents
async function generateDocumentsFromTable() {
    try {
        const metadataSelection = document.getElementById('metadataTemplateDropdown').value;
        const keywordCheckbox = document.getElementById('keywordCheckbox').checked; // Check if the checkbox is enabled

        let metadataTemplateKey = null;
        let metadataFields = [];
        const useJobFolderDirectly = metadataSelection === 'none';

        if (metadataSelection === 'create_new_template') {
            const metadataTemplateName = prompt("Enter the name for your new metadata template:");
            if (!metadataTemplateName) {
                alert("Metadata template name is required to proceed.");
                return;
            }
            metadataTemplateKey = await createMetadataTemplateFromTags(metadataTemplateName);
        } else if (!useJobFolderDirectly) {
            metadataTemplateKey = metadataSelection;
            const templateDetails = await fetchBoxApi(
                `https://api.box.com/2.0/metadata_templates/enterprise/${metadataTemplateKey}/schema`
            );
            metadataFields = templateDetails.fields
                .filter(field => field.type === "string")
                .map(field => field.key);
        }

        const fileInfoResponse = await fetchBoxApi(
            `https://api.box.com/2.0/files/${fileId}?fields=parent,name`
        );
        const parentFolderId = fileInfoResponse.parent.id;
        const csvTemplateName = fileInfoResponse.name.replace(/\.[^/.]+$/, '');
        const randomJobNumber = Math.floor(Math.random() * 10000) + 1;

        const jobFolder = await fetchBoxApi(
            'https://api.box.com/2.0/folders',
            'POST',
            JSON.stringify({
                name: `${csvTemplateName}-${randomJobNumber}`,
                parent: { id: parentFolderId },
            })
        );
        const jobFolderId = jobFolder.id;

        // Get the table rows (first row is assumed to be the header)
        const tableRows = document.querySelectorAll('#tableContainer table tr');
        const totalRows = tableRows.length - 1; // excluding header row
        const headers = Array.from(tableRows[0].querySelectorAll('th, td')).map(cell => cell.textContent);

        // Show the existing loading spinner and set the initial progress message
        const spinner = document.getElementById('loadingSpinner');
        spinner.style.display = 'block';
        spinner.innerText = 'Starting document generation...';

        // Process each data row in the table
        for (let i = 1; i < tableRows.length; i++) {
            // Update progress message using the spinner element
            spinner.innerText = `${i}/${totalRows}`;

            const row = tableRows[i];
            const cells = row.querySelectorAll('td');
            const rowData = {};
            const metadataJson = {};
            console.log(`Generating file #${i}`);

            cells.forEach((cell, index) => {
                const columnName = headers[index] || `Column${index + 1}`;
                const rawValue = cell.textContent.trim();
                rowData[columnName] = rawValue;
                const sanitizedColumnName = sanitizeColumnName(columnName);

                // Add keys if they exist in metadataFields
                if (metadataTemplateKey && metadataFields.includes(sanitizedColumnName)) {
                    metadataJson[sanitizedColumnName] = rawValue;
                }

                // Add date-related keys if keyword-to-format is enabled
                if (keywordCheckbox && sanitizedColumnName.toLowerCase().includes("date")) {
                    metadataJson[sanitizedColumnName] = rawValue;
                }
            });

            // Apply keyword-to-format logic for date fields
            if (keywordCheckbox) {
                Object.keys(metadataJson).forEach((key) => {
                    const rawDate = metadataJson[key];
                    if (key.toLowerCase().includes("date")) {
                        if (!rawDate) {
                            console.warn(`Key "${key}" has no value or is invalid. Skipping...`);
                            return; // Skip processing this key
                        }
                        try {
                            const parsedDate = parseRawDate(rawDate);
                            if (parsedDate) {
                                metadataJson[key] = parsedDate.toISOString(); // Convert to RFC3339
                            } else {
                                console.warn(`Failed to parse date for key "${key}". Removing this key.`);
                                delete metadataJson[key];
                            }
                        } catch (error) {
                            console.error(`Error processing key "${key}":`, error);
                            delete metadataJson[key];
                        }
                    }
                });
            }

            let destinationFolderId = jobFolderId;
            if (!useJobFolderDirectly) {
                const firstValue = rowData[headers[0]] || `Row-${i}`;
                const randomRowNumber = Math.floor(Math.random() * 10000) + 1;
                const rowFolderName = `${firstValue}-${randomRowNumber}`;

                const rowFolder = await fetchBoxApi(
                    'https://api.box.com/2.0/folders',
                    'POST',
                    JSON.stringify({
                        name: rowFolderName,
                        parent: { id: jobFolderId },
                    })
                );
                destinationFolderId = rowFolder.id;
                if (metadataTemplateKey && Object.keys(metadataJson).length > 0) {
                    await applyMetadataToFolder(destinationFolderId, metadataTemplateKey, metadataJson);
                    await createCascadePolicyForFolder(destinationFolderId, metadataTemplateKey);
                }
            }

            await generateDocument(fileId, destinationFolderId, rowData[headers[0]] || `Document-${i}`, rowData);
        }

        // Final progress update and hide the spinner
        spinner.innerText = 'Document generation process completed.';
        spinner.style.display = 'none';

        alert('Documents generation process completed.');
        updateInstructions(5);
    } catch (error) {
        console.error('Error generating documents:', error);
        alert('An error occurred while generating documents.');
    }
}

// Generate a document using the Box API
async function generateDocument(fileId, folderId, fileName, dataJson) {
    try {
        const accessToken = await getValidAccessToken();

        // Convert flat dataJson to nested structure
        const nestedDataJson = createNestedJson(dataJson);

        // Log the cleaned dataJson
        console.log(`Nested Data for ${fileName}:`, nestedDataJson);

        const payload = JSON.stringify({
            file: { type: 'file', id: fileId },
            destination_folder: { type: 'folder', id: folderId },
            input_source: 'api',
            output_type: 'pdf',
            document_generation_data: [
                {
                    generated_file_name: `${fileName}.pdf`,
                    user_input: nestedDataJson,
                },
            ],
        });

        const response = await fetch('https://api.box.com/2.0/docgen_batches', {
            method: 'POST',
            headers: {
                Authorization: `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
            },
            body: payload,
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Failed to generate document: ${errorText}`);
        }

        console.log(`Document generation initiated for ${fileName}.`);
    } catch (error) {
        console.error(`Error generating document for ${fileName}:`, error);
    }
}

// Check or Create Templates Folder
async function checkOrCreateTemplatesFolder(parentFolderId) {
    const folderItems = await fetchBoxApi(`https://api.box.com/2.0/folders/${parentFolderId}/items`);
    const templatesFolder = folderItems.entries.find(item => item.type === 'folder' && item.name === 'templates');

    if (templatesFolder) return templatesFolder.id;

    const newFolder = await fetchBoxApi('https://api.box.com/2.0/folders', 'POST', JSON.stringify({
        name: 'templates',
        parent: { id: parentFolderId },
    }));
    return newFolder.id;
}

// Fetch all metadata templates from the organization
async function getAllMetadataTemplates() {
    const url = 'https://api.box.com/2.0/metadata_templates/enterprise?limit=300';
    const myHeaders = new Headers();
    myHeaders.append("Content-Type", "application/json");
    const accessToken = await getValidAccessToken();
    myHeaders.append("Authorization", `Bearer ${accessToken}`);

    try {
        const response = await fetch(url, { method: 'GET', headers: myHeaders });
        if (!response.ok) {
            const errorDetails = await response.text();
            throw new Error(`HTTP error! Status: ${response.status} - ${errorDetails}`);
        }
        const responseData = await response.json();
        return responseData['entries'];
    } catch (error) {
        console.error('Error getting templates:', error);
        return [];
    }
}

// Display Metadata Template Dropdown
async function displayMetadataTemplateDropdown() {
    const tableContainer = document.getElementById('tableContainer');

    // Remove existing dropdown if it exists
    const existingDropdown = document.getElementById('metadataTemplateDropdown');
    if (existingDropdown) {
        existingDropdown.remove();
    }

    // Create a new dropdown element
    const dropdown = document.createElement('select');
    dropdown.id = 'metadataTemplateDropdown';
    dropdown.style.marginTop = '10px';
    dropdown.style.marginBottom = '10px';
    dropdown.style.width = '100%';
    dropdown.style.padding = '8px';
    dropdown.style.border = '1px solid #ddd';

    // Add the "Do Not Add Metadata" option
    const noMetadataOption = document.createElement('option');
    noMetadataOption.value = 'no_metadata';
    noMetadataOption.textContent = 'Do Not Add Metadata';
    noMetadataOption.selected = true; // Set as the default option
    dropdown.appendChild(noMetadataOption);

    // Add the first option: "Create New Template from Tags"
    const defaultOption = document.createElement('option');
    defaultOption.value = 'create_new_template';
    defaultOption.textContent = 'Create New Template from Tags';
    dropdown.appendChild(defaultOption);

    // Fetch and add existing metadata templates
    try {
        const templates = await getAllMetadataTemplates();
        templates.forEach(template => {
            const option = document.createElement('option');
            option.value = template.templateKey; // Use the template key as the value
            option.textContent = template.displayName; // Use the display name as the option text
            dropdown.appendChild(option);
        });
    } catch (error) {
        console.error('Error fetching metadata templates:', error);
    }

    // Add event listener for dropdown selection
    dropdown.addEventListener('change', () => {
        const selectedValue = dropdown.value;
        if (selectedValue === 'no_metadata') {
            console.log('No metadata will be added.');
        } else if (selectedValue === 'create_new_template') {
            console.log('Create new template selected');
            // Placeholder for creating a new template from tags
        } else {
            console.log(`Selected existing template: ${selectedValue}`);
            // Placeholder for using an existing template
        }
    });

    // Add the dropdown to the table container
    tableContainer.appendChild(dropdown);
}

// Upload CSV File
async function uploadCsvFile(parentFolderId, file) {
    const accessToken = await getValidAccessToken();
    // Generate a random number for uniqueness
    const randomFileNumber = Math.floor(Math.random() * 10000) + 1;

    // Add the random number to the file name (before the extension)
    const fileNameParts = file.name.split('.');
    const baseName = fileNameParts.slice(0, -1).join('.') || file.name; // Handle files without extensions
    const extension = fileNameParts.length > 1 ? `.${fileNameParts.pop()}` : '';
    const newFileName = `${baseName}-${randomFileNumber}${extension}`;

    // Prepare the form data
    const formData = new FormData();
    formData.append('attributes', JSON.stringify({ name: newFileName, parent: { id: parentFolderId } }));
    formData.append('file', file);

    // Upload the file
    const uploadResponse = await fetch('https://upload.box.com/api/2.0/files/content', {
        method: 'POST',
        headers: { Authorization: `Bearer ${accessToken}` },
        body: formData,
    });

    if (!uploadResponse.ok) throw new Error(`Failed to upload file: ${uploadResponse.statusText}`);

    const uploadedFile = await uploadResponse.json();
    return uploadedFile.entries[0].id;
}

// Updated function to display CSV and add the dropdown
function displayCsvAsTable(textRepresentation) {
    const rows = parseCsv(textRepresentation);
    const table = document.createElement('table');

    // Apply table styles
    table.style.width = '100%';
    table.style.borderCollapse = 'collapse';
    table.style.tableLayout = 'fixed';
    table.style.fontSize = '8px';

    rows.forEach((row, rowIndex) => {
        const tr = document.createElement('tr');
        row.forEach(cell => {
            const td = document.createElement(rowIndex === 0 ? 'th' : 'td');
            td.textContent = cell;

            // Apply cell styles
            td.style.whiteSpace = 'nowrap';
            td.style.overflow = 'hidden';
            td.style.textOverflow = 'ellipsis';
            td.style.border = '1px solid #ddd';
            td.style.padding = '8px';

            tr.appendChild(td);
        });
        table.appendChild(tr);
    });

    const tableContainer = document.getElementById('tableContainer');
    tableContainer.innerHTML = ''; // Clear any existing table
    tableContainer.appendChild(table);

    // Add "Generate Documents" button
    const generateDocsButton = createButton('Generate Documents', generateDocumentsFromTable);
    generateDocsButton.className = 'non-picker-button';
    tableContainer.appendChild(generateDocsButton);
}

// Create Metadata Template
function createMetadataTemplate() {
    console.log('Create Metadata Template function placeholder');
}

// Create Button
function createButton(text, callback) {
    const button = document.createElement('button');
    button.textContent = text;
    button.addEventListener('click', callback);
    return button;
}

// function to update the instructions div
function updateInstructions(phase) {
    const instructionsBox = document.getElementById('instructionsBox');
    let instructionsText = '';

    switch (phase) {
        case 1:
            instructionsText = 'Step 1: Select a Doc Gen template from the list.';
            break;
        case 2:
            instructionsText = 'Step 2: now that you have your doc, you can export a csv representing all of the unique tags in the template. Once you have filled out the data you want to use, select "upload template" to upload your data. This will create a new folder called "templates" in the same folder as your template and store the csv there for reference.';
            break;
        case 3:
            instructionsText = 'Step 3: Fill in the CSV with your data and upload it to generate documents.';
            break;
        case 4:
            instructionsText = 'Step 4: Here is the data in your doc. You have a few choices for how you want to handle metadata here. We can bypass this entirely, you can create a new template from that list of keys in the column headers of your csv - and you can name it too, no worries - or you can select an existing template to use for this process. NOTE - we only update fields where the key of the field is an EXACT match to the column name of the csv - the template tag. We will create a new job number in the same folder as the template, and begin the generation process. Also - the "keyword to formatting" checkbox will convert a date string to the correct format for a date value in Box metadata when checked - only do this if the word DATE is included in the metadata field name and you want to save values for that field in a date format';
            break;
        case 5:
            instructionsText = 'Step 5: Perfect! You should have all the files generated and tagged. To go through the process again, reload the app!';
            break;
        default:
            instructionsText = '';
    }

    if (instructionsText) {
        instructionsBox.textContent = instructionsText;
        instructionsBox.classList.remove('hidden');
    } else {
        instructionsBox.classList.add('hidden');
    }
}
