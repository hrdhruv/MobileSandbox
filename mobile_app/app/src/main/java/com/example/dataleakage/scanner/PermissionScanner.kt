class PermissionScanner(val context: Context) {
    fun getInstalledApps(): List<ApplicationInfo> {
        return context.packageManager.getInstalledApplications(PackageManager.GET_META_DATA)
    }

    fun getAppPermissions(packageName: String): List<String> {
        return try {
            val info = context.packageManager.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
            info.requestedPermissions?.toList() ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }
}