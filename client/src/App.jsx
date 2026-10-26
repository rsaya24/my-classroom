import SecurityShell from './SecurityShell';

function App() {
  return <SecurityShell>{props => <Dashboard {...props} />}</SecurityShell>;
}

function Dashboard({ completed, tasks, saving, onComplete, onTask, securityPanel }) {

  const subjects = [
    {
      id: "cloud",
      icon: "☁️",
      name: "Cloud Computing",
      completed: completed.cloud,
      total: 12,
    },
    {
      id: "operating",
      icon: "💻",
      name: "Operating Systems",
      completed: completed.operating,
      total: 10,
    },
    {
      id: "networks",
      icon: "🌐",
      name: "Computer Networks",
      completed: completed.networks,
      total: 10,
    },
  ];

  const totalCompleted = Object.values(completed).reduce(
    (sum, value) => sum + value,
    0
  );

  const totalTopics = subjects.reduce(
    (sum, subject) => sum + subject.total,
    0
  );

  const overallProgress = Math.round(
    (totalCompleted / totalTopics) * 100
  );

  const toggleDemoTask = (subjectId) => {
    onComplete(subjectId, subjects.find(subject => subject.id === subjectId).total);
  };

  return (
    <div className="min-h-screen bg-[#f8f5ff] text-[#292238]">

      {/* Sidebar */}

      <aside className="fixed left-0 top-0 hidden h-screen w-64 border-r border-[#eee8fa] bg-white px-6 py-8 lg:block">

        <div className="mb-12">
          <div className="mb-1 flex items-center gap-2">
            <span className="text-2xl">✦</span>

            <h1 className="text-xl font-bold">
              My Classroom
            </h1>
          </div>

          <p className="text-sm text-[#958ca5]">
            Your personal learning space
          </p>
        </div>

        <nav className="space-y-2">

          <button className="flex w-full items-center gap-3 rounded-2xl bg-[#eee7ff] px-4 py-3 text-left font-semibold text-[#7654c7]">
            <span>⌂</span>
            Dashboard
          </button>

          <button className="flex w-full items-center gap-3 rounded-2xl px-4 py-3 text-left text-[#777080] hover:bg-[#faf8ff]">
            <span>▣</span>
            My Subjects
          </button>

          <button className="flex w-full items-center gap-3 rounded-2xl px-4 py-3 text-left text-[#777080] hover:bg-[#faf8ff]">
            <span>✓</span>
            Today's Tasks
          </button>

          <button className="flex w-full items-center gap-3 rounded-2xl px-4 py-3 text-left text-[#777080] hover:bg-[#faf8ff]">
            <span>✦</span>
            AI Notes
          </button>

          <button className="flex w-full items-center gap-3 rounded-2xl px-4 py-3 text-left text-[#777080] hover:bg-[#faf8ff]">
            <span>◷</span>
            Calendar
          </button>

          <button className="flex w-full items-center gap-3 rounded-2xl px-4 py-3 text-left text-[#777080] hover:bg-[#faf8ff]">
            <span>◒</span>
            Progress
          </button>

        </nav>

        <div className="absolute bottom-8 left-6 right-6">

          <button className="flex w-full items-center gap-3 rounded-2xl px-4 py-3 text-left text-[#777080] hover:bg-[#faf8ff]">
            ⚙️ Settings
          </button>

        </div>

      </aside>


      {/* Main */}

      <main className="px-5 py-8 lg:ml-64 lg:px-10 lg:py-10">

        {/* Header */}

        <header className="mb-8 flex items-center justify-between">

          <div>
            <p className="mb-1 text-sm font-medium text-[#958ca5]">
              {new Date().toLocaleDateString(undefined, { weekday: 'long', month: 'long', day: 'numeric' })}
            </p>

            <h2 className="text-3xl font-bold tracking-tight sm:text-4xl">
              Good afternoon 👋
            </h2>

            <p className="mt-2 text-[#958ca5]">
              Let's make some progress today.
            </p>
          </div>

          <div className="hidden h-12 w-12 items-center justify-center rounded-full bg-[#eee7ff] text-xl sm:flex">
            ✦
          </div>

        </header>

        {securityPanel}


        {/* Progress card */}

        <section className="mb-8 overflow-hidden rounded-[28px] bg-gradient-to-br from-[#7b5ccc] to-[#9b7de5] p-7 text-white shadow-lg shadow-purple-200 sm:p-9">

          <div className="flex flex-col justify-between gap-8 md:flex-row md:items-center">

            <div>

              <p className="mb-2 text-sm font-medium text-purple-100">
                OVERALL PROGRESS
              </p>

              <div className="flex items-end gap-3">

                <span className="text-6xl font-bold tracking-tight">
                  {overallProgress}%
                </span>

                <span className="mb-2 text-sm text-purple-100">
                  syllabus completed
                </span>

              </div>

              <p className="mt-3 text-sm text-purple-100">
                {totalCompleted} of {totalTopics} topics completed
              </p>

            </div>

            <div className="flex items-center gap-4 rounded-3xl bg-white/10 px-6 py-5 backdrop-blur-sm">

              <span className="text-3xl">🔥</span>

              <div>
                <p className="text-2xl font-bold">
                  Saved
                </p>

                <p className="text-xs text-purple-100">
                  per-account progress
                </p>
              </div>

            </div>

          </div>

          <div className="mt-8 h-3 overflow-hidden rounded-full bg-white/20">

            <div
              className="h-full rounded-full bg-white transition-all duration-500"
              style={{ width: `${overallProgress}%` }}
            />

          </div>

        </section>


        {/* Subjects */}

        <section className="mb-8">

          <div className="mb-5 flex items-center justify-between">

            <div>
              <h3 className="text-xl font-bold">
                Your Subjects
              </h3>

              <p className="mt-1 text-sm text-[#958ca5]">
                Keep track of everything you're learning.
              </p>
            </div>

            <button className="rounded-2xl bg-[#292238] px-5 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-[#403553]">
              + Add Subject
            </button>

          </div>


          <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">

            {subjects.map((subject) => {

              const progress = Math.round(
                (subject.completed / subject.total) * 100
              );

              return (

                <div
                  key={subject.id}
                  className="group rounded-[26px] border border-[#eee8fa] bg-white p-6 shadow-sm transition duration-300 hover:-translate-y-1 hover:shadow-lg"
                >

                  <div className="mb-5 flex items-start justify-between">

                    <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-[#f2edff] text-2xl">
                      {subject.icon}
                    </div>

                    <button className="text-xl text-[#aaa2b4]">
                      ···
                    </button>

                  </div>

                  <h4 className="text-lg font-bold">
                    {subject.name}
                  </h4>

                  <p className="mt-1 text-sm text-[#958ca5]">
                    {subject.completed} / {subject.total} topics completed
                  </p>

                  <div className="mt-5 h-2 overflow-hidden rounded-full bg-[#f0ecf5]">

                    <div
                      className="h-full rounded-full bg-[#8768d4] transition-all duration-500"
                      style={{ width: `${progress}%` }}
                    />

                  </div>

                  <div className="mt-3 flex items-center justify-between">

                    <span className="text-sm font-semibold text-[#7654c7]">
                      {progress}%
                    </span>

                    <button
                      onClick={() => toggleDemoTask(subject.id)}
                      disabled={saving}
                      className="text-xs font-semibold text-[#958ca5] hover:text-[#7654c7]"
                    >
                      + Complete topic
                    </button>

                  </div>

                </div>

              );
            })}

          </div>

        </section>


        {/* Today's tasks */}

        <section className="rounded-[26px] border border-[#eee8fa] bg-white p-6 shadow-sm sm:p-7">

          <div className="mb-6">

            <h3 className="text-xl font-bold">
              Today's Tasks
            </h3>

            <p className="mt-1 text-sm text-[#958ca5]">
              Your next little steps.
            </p>

          </div>

          <div className="space-y-2">

            <Task
              title="Revise Cloud Service Models"
              subject="Cloud Computing"
              completed={tasks['cloud-models']}
              onToggle={() => onTask('cloud-models')}
              disabled={saving}
            />

            <Task
              title="Read Process Scheduling"
              subject="Operating Systems"
              completed={tasks['process-scheduling']}
              onToggle={() => onTask('process-scheduling')}
              disabled={saving}
            />

            <Task
              title="Study TCP/IP"
              subject="Computer Networks"
              completed={tasks['tcp-ip']}
              onToggle={() => onTask('tcp-ip')}
              disabled={saving}
            />

            <Task
              title="Review Virtualization"
              subject="Cloud Computing"
              completed={tasks.virtualization}
              onToggle={() => onTask('virtualization')}
              disabled={saving}
            />

          </div>

        </section>

      </main>

    </div>
  );
}


function Task({ title, subject, completed: isCompleted = false, onToggle, disabled }) {

  return (

    <div className="flex items-center gap-4 rounded-2xl px-3 py-4 transition hover:bg-[#faf8ff]">

      <button
        onClick={onToggle}
        disabled={disabled}
        aria-label={`Toggle ${title}`}
        aria-pressed={isCompleted}
        className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border-2 transition ${
          isCompleted
            ? "border-[#8768d4] bg-[#8768d4] text-white"
            : "border-[#d8d0e2] bg-white"
        }`}
      >
        {isCompleted && "✓"}
      </button>

      <div className="min-w-0 flex-1">

        <p
          className={`font-medium ${
            isCompleted
              ? "text-[#aaa2b4] line-through"
              : "text-[#393044]"
          }`}
        >
          {title}
        </p>

        <p className="mt-1 text-xs text-[#aaa2b4]">
          {subject}
        </p>

      </div>

      <span className="hidden rounded-full bg-[#f2edff] px-3 py-1 text-xs font-medium text-[#7654c7] sm:block">
        Study
      </span>

    </div>

  );
}

export default App;
