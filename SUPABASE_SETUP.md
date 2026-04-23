# Supabase Backend Setup

This project now uses Supabase as the backend service. Follow these steps to configure it.

## 1. Create a Supabase Project
1. Go to [database.new](https://database.new) and create a new project.
2. Note your **Project URL** and **API Key (anon/public)** from the dashboard (Settings > API).

## 2. Configure Environment Variables
1. Open `.env` in the project root.
2. Update the following values:
   ```env
   SUPABASE_URL=your_project_url
   SUPABASE_ANON_KEY=your_anon_key
   # Optional: For smoother user migration (bypassing email confirmation)
   # SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
   ```

## 3. Setup Database Schema
1. Open the **SQL Editor** in your Supabase Dashboard.
2. Open `supabase_schema.sql` from this project.
3. Copy the entire content and paste it into the SQL Editor.
4. Click **Run** to create tables, policies, and triggers.

## 4. Setup Storage
1. Go to **Storage** in Supabase Dashboard.
2. Create a new bucket named `uploads`.
3. Set the bucket to **Public**.
4. (Optional) Add a policy to allow authenticated uploads if not already handled by your schema/dashboard settings.
   - The provided schema includes basic RLS but you might need to ensure the bucket is publicly readable.

## 5. Migrate Data (Optional)
If you have existing data in `data/*.json` files (from the previous local version):
1. Ensure your `.env` is configured.
2. Run the migration script:
   ```bash
   npm run migrate
   ```
3. This will:
   - Create Supabase users for each user in `users.json` (Default password: `ChangeMe123!`).
   - Migrate tracks, status events, and catches.
   - Upload local images to Supabase Storage.

## 6. Start the Server
```bash
npm start
```
The server will now use Supabase for authentication and data storage.
