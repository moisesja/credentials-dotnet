namespace Credentials.BbsGate;

/// <summary>
/// What the gate needs to keep its one promise about files: it never deletes, overwrites or truncates
/// anything it did not create in the same run.
/// </summary>
internal static class Paths
{
    /// <summary>
    /// Whether a path is inside a folder: below it, and not the folder itself. By the full paths, compared
    /// letter for letter. A folder named <c>..name</c> is a name like any other, and a path on another
    /// drive is not inside.
    /// </summary>
    public static bool IsInside(string folder, string path) =>
        Path.TrimEndingDirectorySeparator(Path.GetFullPath(path)).StartsWith(
            Path.TrimEndingDirectorySeparator(Path.GetFullPath(folder)) + Path.DirectorySeparatorChar, StringComparison.Ordinal);

    /// <summary>
    /// Copies a folder to a place that is not there yet. Nothing is overwritten: a file that is already
    /// at its destination stops the copy. Each destination is passed through <paramref name="mine"/>, which
    /// refuses a path outside the gate's own folder. And the gate's own folder is never copied into
    /// itself: a folder that <paramref name="isOwn"/> knows for it stops the copy, by whatever path, link
    /// or spelling the copy came to it.
    /// </summary>
    /// <param name="from">The folder to copy.</param>
    /// <param name="to">Where to.</param>
    /// <param name="skip">Names of folders directly in <paramref name="from"/> to leave out.</param>
    /// <param name="mine">Returns the path if the gate may write there, and throws if not.</param>
    /// <param name="isOwn">Whether a folder is the one the gate made for this run.</param>
    public static void Copy(string from, string to, string[] skip, Func<string, string> mine, Func<string, bool> isOwn)
    {
        if (isOwn(from))
        {
            throw new InvalidOperationException($"{from} is the folder the gate made for this run, and it is inside what the gate "
                + "copies: the work folder is under tests/ or in the folder of a test assembly, by this name or another.");
        }

        Directory.CreateDirectory(mine(to));
        foreach (var file in Directory.EnumerateFiles(from))
        {
            File.Copy(file, mine(Path.Combine(to, Path.GetFileName(file))), overwrite: false);
        }

        foreach (var directory in Directory.EnumerateDirectories(from).Where(directory => !skip.Contains(Path.GetFileName(directory))))
        {
            Copy(directory, Path.Combine(to, Path.GetFileName(directory)), skip: [], mine, isOwn);
        }
    }
}

/// <summary>
/// The one folder a run of the gate makes and may delete. It is new: a name that is taken stops the gate,
/// and a folder that was there is never the gate's own. A file in it with a name of its own tells the
/// folder apart from every other, whatever path leads to it.
/// </summary>
internal sealed class OwnFolder
{
    private readonly string _mark;

    private OwnFolder(string path, string mark)
    {
        Path = path;
        _mark = mark;
    }

    /// <summary>The full path of the folder.</summary>
    public string Path { get; }

    /// <summary>Makes a new folder in <paramref name="parent"/>, which has to be there.</summary>
    /// <param name="parent">The folder to make it in.</param>
    /// <param name="name">Gives a name for it.</param>
    /// <exception cref="InvalidOperationException">Something of that name is there already. Nothing is touched.</exception>
    public static OwnFolder MakeIn(string parent, Func<string> name)
    {
        var path = System.IO.Path.Combine(parent, name());
        if (Directory.Exists(path) || File.Exists(path))
        {
            throw new InvalidOperationException($"{path} is already there, and it is not this run's. The gate works only in a folder it has made itself; run it again.");
        }

        // Only now is there anything of the gate's: what was there before is not it, and is left alone.
        Directory.CreateDirectory(path);
        var mark = ".bbs-gate-" + Guid.NewGuid().ToString("N");
        File.WriteAllText(System.IO.Path.Combine(path, mark), "The folder of one run of the bbs-2023 gate.\n");
        return new OwnFolder(path, mark);
    }

    /// <summary>Whether a folder, by whatever path, is this one.</summary>
    public bool Is(string folder) => File.Exists(System.IO.Path.Combine(folder, _mark));
}
