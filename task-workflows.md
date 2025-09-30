# Task Management Workflows

This document outlines the workflows for managing tasks, including creation, assignment, and retrieval. It also details the integration with the project and WBS (Work Breakdown Structure) services.

## 1. Task Lifecycle

### 1.1. Creating a Task

A new task is created by sending a `POST` request to the `/` endpoint.

- **Endpoint**: [`POST /`](#)
- **Description**: Creates a new task.
- **Request Body**: The request body should contain the task details, such as title, description, and due date.

**Example:**
```json
{
  "title": "Implement user authentication",
  "description": "Develop and integrate the user login and registration functionality.",
  "dueDate": "2025-09-15"
}
```

### 1.2. Retrieving Tasks

Tasks can be retrieved individually or as a list.

- **Endpoint**: [`GET /`](#)
- **Description**: Retrieves a list of all tasks.

- **Endpoint**: [`GET /:id`](#)
- **Description**: Retrieves a single task by its unique identifier.

### 1.3. Updating a Task

To update an existing task, send a `PUT` request to the `/:id` endpoint.

- **Endpoint**: [`PUT /:id`](#)
- **Description**: Updates the details of a specific task.
- **Request Body**: The request body should contain the fields to be updated.

**Example:**
```json
{
  "status": "in-progress"
}
```

### 1.4. Deleting a Task

A task can be deleted by sending a `DELETE` request to the `/:id` endpoint.

- **Endpoint**: [`DELETE /:id`](#)
- **Description**: Deletes a specific task.

## 2. User Assignment

### 2.1. Assigning Users to a Task

Users can be assigned to a task to delegate responsibility.

- **Endpoint**: [`POST /:id/assign`](#)
- **Description**: Assigns one or more users to a task.
- **Request Body**: Should contain a list of user IDs to be assigned.

**Example:**
```json
{
  "userIds": ["user-123", "user-456"]
}
```

### 2.2. Unassigning Users from a Task

To remove users from a task, use the unassign endpoint.

- **Endpoint**: [`POST /:id/unassign`](#)
- **Description**: Unassigns one or more users from a task.
- **Request Body**: Should contain a list of user IDs to be unassigned.

**Example:**
```json
{
  "userIds": ["user-123"]
}
```

## 3. Service Integrations

### 3.1. Project Integration

Tasks are associated with projects, allowing for better organization and tracking.

- **Endpoint**: [`GET /projects/:projectId/tasks`](#)
- **Description**: Retrieves a list of all tasks associated with a specific project.

### 3.2. WBS (Work Breakdown Structure) Integration

Tasks can be linked to specific nodes in a project's WBS.

- **Endpoint**: [`GET /projects/:projectId/wbs/:nodeId/tasks`](#)
- **Description**: Retrieves a list of tasks for a specific WBS node within a project. This allows for granular task management within the project's structure.